// gcc -o main main.c -I /usr/local/include/vfio-user/ -lvfio-user -lpthread -lpci
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <pci/pci.h>
#include <libvfio-user.h>

vfu_ctx_t *vfu_ctx;

#define VFIO_GROUP_PATH "/dev/vfio/vfio"
#define VFIO_CONTAINER_PATH "/dev/vfio/vfio"

#define VFIO_USER_PATH "/tmp/vfio-user.sock"

char *region_names[] = {
    "CONFIG",
    "BAR0",
    "BAR1",
    "BAR2",
    "BAR3",
    "BAR4",
    "BAR5",
    "ROM",
    "VGA"
};

char *irq_names[] = {
    "INTX",
    "MSI",
    "MSIX",
    "ERR",
    "REQ"
};

typedef struct pci_device_info {
    uint16_t vid, did;
    uint8_t base_class, sub_class, prog_if;
} pci_device_info_t;

int get_pci_device_info(const char* device_bdf, pci_device_info_t *info) {
    struct pci_access *pacc;
    struct pci_dev *dev;
    int found = 0;

    pacc = pci_alloc();
    pci_init(pacc);
    pci_scan_bus(pacc);

    for (dev = pacc->devices; dev; dev = dev->next) {
        char device_str[13];
        pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);	/* Fill in header info we need */
        snprintf(device_str, sizeof(device_str), "%04x:%02x:%02x.%d",
                 dev->domain, dev->bus, dev->dev, dev->func);
        if (strcmp(device_bdf, device_str) == 0) {
            found = 1;
            info->vid = dev->vendor_id;
            info->did = dev->device_id;
            // Adjusted for direct access without subsystem ID specifics
            info->base_class = (uint8_t)(dev->device_class >> 16);
            info->sub_class = (uint8_t)(dev->device_class >> 8);
            info->prog_if = (uint8_t)dev->device_class;
            break;
        }
    }

    pci_cleanup(pacc);
    return found;
}

char *vfio_group_from_pcidev(char *device) {
    char vfio_group_path[PATH_MAX];
    ssize_t len;
    char *vfio_group;

    snprintf(vfio_group_path, sizeof(vfio_group_path), "/sys/bus/pci/devices/%s/iommu_group", device);
    len = readlink(vfio_group_path, vfio_group_path, sizeof(vfio_group_path) - 1);
    if (len < 0) {
        perror("Failed to readlink iommu_group");
        return NULL;
    }
    vfio_group_path[len] = '\0';
    vfio_group = strrchr(vfio_group_path, '/') + 1;
    if (!vfio_group) {
        perror("Failed to get IOMMU group");
        return NULL;
    }
    return vfio_group;
}

int vfio_device_open_fd(char *device, int *container_fd, int *group_fd)
{
    int container, group, device_fd;
    struct vfio_group_status group_status = {.argsz = sizeof(group_status)};
    char device_path[PATH_MAX];
    char vfio_group_path[PATH_MAX];
    ssize_t len;
    char *vfio_group;

    vfio_group = vfio_group_from_pcidev(device);

    printf("Opening VFIO group %s...\n", vfio_group);
    // Open the VFIO container
    container = open(VFIO_CONTAINER_PATH, O_RDWR);
    if (container < 0) {
        perror("Failed to open VFIO container");
        return -1;
    }

    // Open the group
    snprintf(device_path, sizeof(device_path), "/dev/vfio/%s", vfio_group);
    group = open(device_path, O_RDWR);
    if (group < 0) {
        perror("Failed to open VFIO group");
        close(container);
        return -1;
    }

    // Check if the group is viable
    if (ioctl(group, VFIO_GROUP_GET_STATUS, &group_status) < 0 || !(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        perror("VFIO group is not viable or failed to get status");
        close(group);
        close(container);
        return -1;
    }

    // Add the group to the container
    if (ioctl(group, VFIO_GROUP_SET_CONTAINER, &container) < 0) {
        perror("Failed to set VFIO container for group");
        close(group);
        close(container);
        return -1;
    }

    // Set the IOMMU type
    if (ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
        perror("Failed to set IOMMU type");
        close(group);
        close(container);
        return -1;
    }

    // Get device file descriptor
    device_fd = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, device);
    if (device_fd < 0) {
        perror("Failed to get device FD");
        close(group);
        close(container);
        return -1;
    }

    *container_fd = container;
    *group_fd = group;

    return device_fd;
}

struct region_desc {
    uint64_t size;
    uint64_t offset;
    uint32_t flags;
};

void describe_regions(int device_fd, struct region_desc *descs)
{
    struct vfio_region_info reg = { .argsz = sizeof(reg) };

    // Iterate through all possible regions the device might support
    for (reg.index = 0; reg.index < VFIO_PCI_NUM_REGIONS; reg.index++) {
        ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
        printf("Region %s: ", region_names[reg.index]);
        if (reg.flags & VFIO_REGION_INFO_FLAG_MMAP) {
            printf("mappable, ");
        } else {
            printf("non-mappable, ");
        }
        printf("size: %llu, offset: %llx\n", reg.size, reg.offset);
        descs[reg.index].size = reg.size;
        descs[reg.index].offset = reg.offset;
        descs[reg.index].flags = reg.flags;
    }
}

struct irq_desc {
    uint32_t flags;
    uint32_t count;
};

void describe_interrupts(int device_fd, struct irq_desc *descs)
{
    struct vfio_irq_info irq = { .argsz = sizeof(irq) };

    // Iterate through all possible interrupts the device might support
    for (irq.index = 0; irq.index < VFIO_PCI_NUM_IRQS; irq.index++) {
        ioctl(device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
        printf("Interrupt %s: ", irq_names[irq.index]);
        if (irq.flags & VFIO_IRQ_INFO_EVENTFD) {
            printf("eventfd, ");
        }
        if (irq.flags & VFIO_IRQ_INFO_MASKABLE) {
            printf("maskable, ");
        }
        if (irq.flags & VFIO_IRQ_INFO_AUTOMASKED) {
            printf("automasked, ");
        }
        if (irq.flags & VFIO_IRQ_INFO_NORESIZE) {
            printf("noresize, ");
        }
        printf("count: %u\n", irq.count);
        descs[irq.index].flags = irq.flags;
        descs[irq.index].count = irq.count;
    }
}

int container, group, device;

// declare array of region buffers
char *region_buffers[VFIO_PCI_NUM_REGIONS] = {0};

ssize_t reg_access(int region_idx, vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    if (!region_buffers[region_idx]) {
        if (is_write) {
            return pwrite(device, buf, count, offset);
        } else {
            return pread(device, buf, count, offset);
        }
    }
    if (is_write) {
        memcpy(region_buffers[region_idx] + offset, buf, count);
    } else {
        memcpy(buf, region_buffers[region_idx] + offset, count);
    }
    return 0;
}

ssize_t reg_0_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(0, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_1_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(1, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_2_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(2, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_3_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(3, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_4_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(4, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_5_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(5, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_6_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(6, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_7_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(7, vfu_ctx, buf, count, offset, is_write);
}
ssize_t reg_8_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset, bool is_write)
{
    return reg_access(8, vfu_ctx, buf, count, offset, is_write);
}
// declare array of vfu_region_access_cb_t function pointers
vfu_region_access_cb_t *region_access[VFIO_PCI_NUM_REGIONS] = {
    reg_0_access,
    reg_1_access,
    reg_2_access,
    reg_3_access,
    reg_4_access,
    reg_5_access,
    reg_6_access,
    reg_7_access,
    reg_8_access
};

void irq_state_changed(vfu_ctx_t *vfu_ctx, uint32_t start, uint32_t count, bool mask)
{
    printf("IRQ state changed\n");
    exit(1);
}

struct irq_thread_args {
    int efd;
    int irq_idx;
    int irq_num;
};

void *irq_thread(void *arg)
{
    struct irq_thread_args *args = (struct irq_thread_args *)arg;
    uint64_t val;
    ssize_t len;

    while (1) {
        len = read(args->efd, &val, sizeof(val));
        if (len < 0) {
            perror("Failed to read eventfd");
            return NULL;
        }
        printf("IRQ %s %d triggered\n", irq_names[args->irq_idx], args->irq_num);
        for (int i = 0; i < val; i++) {
            printf("IRQ %s %d triggered %d\n", irq_names[args->irq_idx], args->irq_num, i);
            vfu_irq_trigger(vfu_ctx, args->irq_num);
        }
    }
}

static int device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t type)
{
    char *reset_types[] = {
        "VFU_RESET_DEVICE",
        "VFU_RESET_SUBSYSTEM",
        "VFU_RESET_DOMAIN",
        "VFU_RESET_BUS",
        "VFU_RESET_IOMMU",
        "VFU_RESET_PCI"
    };
    printf("Device reset type %s\n", reset_types[type]);
    exit(1);
    return 0;
}

int main(int argc, char *argv[])
{
    ssize_t len;
    int ret;

    if (argc != 3) {
        printf("Usage: %s <Bus:Device.Function> <socket>\n", argv[0]);
        return -1;
    }

    pci_device_info_t info;
    if (!get_pci_device_info(argv[1], &info)) {
        printf("Failed to get PCI device info\n");
        return -1;
    }
    printf("PCI device %s: VID %04x, DID %04x, class %02x:%02x:%02x\n", argv[1], info.vid, info.did, info.base_class, info.sub_class, info.prog_if);

    // Open the VFIO container, group, and finally the device
    device = vfio_device_open_fd(argv[1], &container, &group);
    if (device < 0) {
        perror("Failed to open VFIO device");
        return -1;
    }

    // Get device info
    struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
    ioctl(device, VFIO_DEVICE_GET_INFO, &device_info);
    printf("Device %s: %d regions, %d irqs\n", argv[1], device_info.num_regions, device_info.num_irqs);

    struct region_desc region_descs[VFIO_PCI_NUM_REGIONS];
    describe_regions(device, region_descs);
    struct irq_desc irq_descs[VFIO_PCI_NUM_IRQS];
    describe_interrupts(device, irq_descs);

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, argv[2], 0, NULL, VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        perror("Failed to create VFIO-User context");
        return -1;
    }

    if (vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0) < 0) {
        perror("Failed to initialize PCI device");
        return -1;
    }

    vfu_pci_set_id(vfu_ctx, info.vid, info.did, 0, 0);

    vfu_pci_set_class(vfu_ctx, info.base_class, info.sub_class, info.prog_if);

    char *config_space = vfu_pci_get_config_space(vfu_ctx);
    if (config_space == NULL) {
        perror("Failed to get config space");
        return -1;
    }
    pwrite(device, region_buffers[0], region_descs[0].size, 0);
    for (int i = 0; i < VFIO_PCI_NUM_REGIONS; i++) {
        int mmap_flags = 0;
        int flags = 0;
        if (region_descs[i].size == 0) {
            continue;
        }
        if (region_descs[i].flags & VFIO_REGION_INFO_FLAG_READ) {
            mmap_flags |= PROT_READ;
            flags |= VFU_REGION_FLAG_READ;
        }
        if (region_descs[i].flags & VFIO_REGION_INFO_FLAG_WRITE) {
            mmap_flags |= PROT_WRITE;
            flags |= VFU_REGION_FLAG_WRITE;
        }
        if (region_descs[i].flags & VFIO_REGION_INFO_FLAG_MMAP) {
            flags |= VFU_REGION_FLAG_MEM;
            // Map the region to VFIO device
            region_buffers[i] = mmap(NULL, region_descs[i].size, mmap_flags, MAP_SHARED, device, region_descs[i].offset);
            if (region_buffers[i] == MAP_FAILED) {
                perror("Failed to mmap region");
                return -1;
            }
            printf("VFIO region %s mapped to %p\n", region_names[i], region_buffers[i]);
        }
        if (vfu_setup_region(vfu_ctx, i, region_descs[i].size, region_access[i], flags, NULL, 0, -1, 0) < 0) {
            perror("Failed to setup region");
            return -1;
        }
        printf("Mapped region %s to VFIO-User\n", region_names[i]);
    }

    int best_irq_type = 0;
    int efd_count = 0;
    for (int i = VFIO_PCI_MSIX_IRQ_INDEX; i > 0; i--) {
        if (irq_descs[i].count > 0) {
            best_irq_type = i;
            efd_count = irq_descs[i].count;
            break;
        }
    }

    printf("Setup IRQ %s count %d\n", irq_names[best_irq_type], irq_descs[best_irq_type].count);
    vfu_setup_device_nr_irqs(vfu_ctx, best_irq_type, irq_descs[best_irq_type].count);
    vfu_setup_irq_state_callback(vfu_ctx, best_irq_type, irq_state_changed);

    pthread_t *efd_threads = malloc(efd_count * sizeof(pthread_t));
    int *efds = malloc(efd_count * sizeof(int));

    for (int i = 0; i < efd_count; i++) {
        printf("Setup IRQ %s %d\n", irq_names[best_irq_type], i);
        struct vfio_irq_set *irq_set = malloc(sizeof(struct vfio_irq_set) + sizeof(struct irq_thread_args));
        struct irq_thread_args *args = (struct irq_thread_args *)irq_set->data;
        efds[i] = eventfd(0, EFD_CLOEXEC);
        args->efd = efds[i];
        args->irq_idx = best_irq_type;
        args->irq_num = i;
        irq_set->argsz = sizeof(struct vfio_irq_set) + sizeof(struct irq_thread_args);
        irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set->index = best_irq_type;
        irq_set->start = i;
        irq_set->count = 1;
        if (ioctl(device, VFIO_DEVICE_SET_IRQS, irq_set) < 0) {
            perror("Failed to setup IRQ");
            return -1;
        }
        free(irq_set);
        pthread_create(&efd_threads[i], NULL, irq_thread, args);
    }
    if (vfu_realize_ctx(vfu_ctx) < 0) {
        perror("Failed to realize VFIO-User device");
        return -1;
    }
    printf("Device realized\n");
    if (vfu_attach_ctx(vfu_ctx) < 0) {
        perror("Failed to attach VFIO-User device");
        return -1;
    }
    printf("Device attached\n");
    do {
        printf(".");
        ret = vfu_run_ctx(vfu_ctx);
        if (ret == -1 && errno == EINTR) {
            printf("x");
            continue;
        }
    } while (ret == 0);
    // Cleanup
    for (int i = 0; i < efd_count; i++) {
        pthread_cancel(efd_threads[i]);
        close(efds[i]);
    }
    close(device);
    close(group);
    close(container);
    return 0;
}
