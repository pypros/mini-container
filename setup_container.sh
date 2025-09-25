#!/bin/bash

# Set options to make the script exit on the first error
set -e

CONTAINER_ROOT="./my_alpine_root"
CGROUP_NAME="my_custom_container_$(date +%s)"
ALPINE_TARBALL="alpine-minirootfs-3.22.1-x86_64.tar.gz"
ALPINE_URL="http://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/$ALPINE_TARBALL"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"

remove_container() {
    echo "Removing previous files and directories..."
    sudo umount "$CONTAINER_ROOT/dev" 2>/dev/null || true
    sudo rm -rf "$CONTAINER_ROOT"
    if [ -d "$CGROUP_PATH" ]; then
        echo "Removing old cgroup..."
        sudo rmdir "$CGROUP_PATH" 2>/dev/null || true
        echo "Old cgroup successfully removed."
    fi
}

create_container() {
    echo "Preparing the container environment..."

    # Download and prepare the filesystem
    if [ ! -f "$ALPINE_TARBALL" ]; then
        echo "Downloading minimal Alpine filesystem..."
        wget "$ALPINE_URL"
    fi

    echo "Extracting minimal Alpine filesystem to: $CONTAINER_ROOT"
    sudo mkdir -p "$CONTAINER_ROOT"
    sudo tar -xzf "$ALPINE_TARBALL" -C "$CONTAINER_ROOT"

    echo "Filesystem prepared at: $CONTAINER_ROOT"

    # Mount devtmpfs from the host into the container directory
    echo "Mounting /dev in the container..."
    sudo mount -t devtmpfs none "$CONTAINER_ROOT/dev"

    # Cgroups (Control Groups) configuration
    echo "Configuring cgroups for resource limiting..."
    if ! mountpoint -q /sys/fs/cgroup; then
        echo "Mounting cgroup2..."
        sudo mount -t cgroup2 none /sys/fs/cgroup
    fi

    sudo mkdir -p "$CGROUP_PATH"
    echo "Setting memory limit to 256MB..."
    sudo sh -c "echo 256M > $CGROUP_PATH/memory.max"
    echo "Setting CPU limit to 50%..."
    sudo sh -c "echo '50000 100000' > $CGROUP_PATH/cpu.max"
    echo "Cgroups configured."

    # Launching the Container with --kill-child
    echo "Launching the process in an isolated environment..."
    sudo unshare \
        --uts \
        --pid \
        --net \
        --mount \
        --user \
        --kill-child \
        --map-root-user \
        --root="$CONTAINER_ROOT" \
        /bin/sh -c "
            # Mount proc and sysfs in the new namespace
            mount -t proc proc /proc;
            mount -t sysfs sys /sys;
            hostname 'my-alpine-host';
            echo 'Welcome to my Alpine container!';
            echo My PID is: \$\$;
            /bin/sh
        "
}

case "$1" in
    create)
        create_container
        ;;
    remove)
        remove_container
        ;;
    *)
        echo "Użycie: $0 {create|remove}"
        exit 1
        ;;
esac