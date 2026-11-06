#!/bin/sh
# ltv-hook: Start Dropbear for push-to-stdin LUKS unlock
# Runs after configure_ip, before nlplug-findfs

. /lib/mkinitfs/ltv-common.sh

# Create forced-command script for future push-to-stdin unlock
if [ ! -f /tmp/ltv-unlock.sh ]; then
    printf '#!/bin/sh\ncryptsetup open --key-file=- "UUID=$1" "$2"\n' > /tmp/ltv-unlock.sh
    chmod +x /tmp/ltv-unlock.sh
fi

# Start Dropbear SSH server
dropbear -E -p 22 -r /etc/dropbear/dropbear_ed25519_host_key &