#!/bin/sh

# this script is used as a trigger to reapply the LTV patch to initramfs-init script

fatal_error() {
    echo "please inspect /usr/share/mkinitfs/initramfs-init as LTV functionality could not be inserted"
    echo " -> no remote unlocking of crypted partitions possible"
    exit 1
}

if [ "$1" = "post-commit" ]; then
    # Check whether mkinitfs appears in the last entries of the current minute's log
    if tail -n 20 /var/log/apk.log | grep -E "installing mkinitfs|upgrading mkinitfs" > /dev/null; then
        echo "-> [ltv-patch] mkinitfs update detected !"
        echo "-> [ltv-patch] Restoring modified initramfs-init..."

        # 2. Copy your modified file over it
        /etc/mkinitfs/ltv-stuff/ltv-patch-init.sh || fatal_error


        # 3. Manually run mkinitfs for all installed kernel versions
        for kv in /lib/modules/*; do
            if [ -d "$kv" ]; then
                kernel_version=$(basename "$kv")
                mkinitfs "$kernel_version"
            fi
        done

        echo "-> [ltv-patch] Done! All boot images are up to date."
    fi
fi
