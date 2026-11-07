#!/bin/sh
# ltv-hook: Start Dropbear for push-to-stdin LUKS unlock
# Runs after configure_ip, before nlplug-findfs
# Dropbear runs in background; init continues to nlplug-findfs which
# waits for /dev/mapper/cryptroot to appear (created by remote unlock).

. /usr/share/mkinitfs/ltv-common.sh

# Create forced-command script for future push-to-stdin unlock
if [ ! -f /tmp/ltv-unlock.sh ]; then
	printf '#!/bin/sh\ncryptsetup open --key-file=- "UUID=$1" "$2"\n' > /tmp/ltv-unlock.sh
	chmod +x /tmp/ltv-unlock.sh
fi

# Start Dropbear SSH server in background; init must continue to nlplug-findfs
dropbear -E -p 22 -r /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key -D /etc/mkinitfs/ltv-stuff/root/.ssh/ &

