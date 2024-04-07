#!/bin/bash

echo "0000:09:00.0" > /sys/bus/pci/drivers/ixgbe/unbind
echo "0000:09:00.1" > /sys/bus/pci/drivers/ixgbe/unbind

DEVS="0000:09:00.0 0000:09:00.1"

if [ ! -z "$(ls -A /sys/class/iommu)" ]; then
    for DEV in $DEVS; do
        echo "vfio-pci" > /sys/bus/pci/devices/$DEV/driver_override
    done
fi

modprobe vfio-pci
