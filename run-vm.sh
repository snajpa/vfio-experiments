#!/usr/bin/env bash

./cloud-hypervisor-static \
    --api-socket=/tmp/ch-api.sock \
    --cpus boot=4 \
    --memory size=8G,shared=on \
    --disk path=./noble/noble-server-cloudimg-amd64.raw \
    --kernel ./noble/firmware \
    --cmdline "root=/dev/vda1 console=ttyS0 verbose" \
    --serial tty \
    --user-device socket=/tmp/vfio-user.sock 

