#!/bin/sh
# ltv-hook: Start Dropbear for push-to-stdin LUKS unlock
# Runs after configure_ip, before nlplug-findfs
# Dropbear runs in background; init continues to nlplug-findfs which
# waits for /dev/mapper/cryptroot to appear (created by remote unlock).

. /usr/share/mkinitfs/ltv-common.sh

# Start Dropbear SSH server in background; init must continue to nlplug-findfs
# Port is configured at deploy time via server-setup (template: {port})
dropbear -E -p {port} -r /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key -D /etc/mkinitfs/ltv-stuff/root/.ssh/ &
