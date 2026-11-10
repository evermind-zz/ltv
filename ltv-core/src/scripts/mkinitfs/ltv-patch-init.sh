#!/bin/sh
# Patch Alpine initramfs-init for LTV remote LUKS unlock (idempotent, POSIX sh)
# Usage: patch-init.sh [INIT_PATH]

set -eu

INIT_PATH="${1:-/usr/share/mkinitfs/initramfs-init}"

# read file
content=$(cat "$INIT_PATH")

# --- Idempotency check ---
if echo "$content" | grep -q '### LTV PATCH START: network setup + dropbear for remote LUKS unlock ###'; then
    echo "[$INIT_PATH] Already patched"
    exit 0
fi

# --- 1. Add 'ltv' to myopts (before alpine_repo) ---
content=$(printf '%s\n' "$content" | awk '
    BEGIN { inserted=0 }
    /^myopts="BOOTIF/ { in_myopts=1 }
    in_myopts && !inserted && /^[[:space:]]*alpine_repo$/ {
        print "\tltv"
        inserted=1
    }
    { print }
')

# verify insertion succeeded
if ! printf '%s\n' "$content" | grep -q '^[[:space:]]*ltv$'; then
    echo "ERROR: failed to insert 'ltv' into myopts" >&2
    exit 1
fi

# --- 2. Insert LTV hook before the zpool/ntab anchor line ---
anchor="# zpool reports /dev/zfs missing if it can.t read /etc/mtab"
# The anchor in file has a literal single quote. Match with regex.
if ! printf '%s\n' "$content" | grep -q "$anchor"; then
    echo "ERROR: anchor line not found" >&2
    exit 1
fi

# Use awk to insert hook before the anchor line
content=$(printf '%s\n' "$content" | awk -v anchor="$anchor" '
    BEGIN { done=0 }
    $0 ~ anchor && !done {
        print "### LTV PATCH START: network setup + dropbear for remote LUKS unlock ###"
        print "### inserted after other network boot setups (e.g. KOPT_nbd, wireguard) ###"
        print "if [ -n \"$KOPT_ltv\" ] && $do_networking; then"
        print "\tconfigure_ip"
        print "\t. /usr/share/mkinitfs/ltv-hook.sh"
        print "fi"
        print "### LTV PATCH END: network setup + dropbear for remote LUKS unlock ###"
        print ""
        done=1
    }
    { print }
')

# --- 3. Replace nlplug-findfs call with ltv-luks-wrapper ---
# Find the line with: $MOCK nlplug-findfs $cryptopts -p /sbin/mdev ...
# and replace it with the wrapper call
content=$(printf '%s\n' "$content" | awk '
    /^\s*\$MOCK nlplug-findfs \$cryptopts -p \/sbin\/mdev/ && !done {
        print "\t# LTV: replace nlplug-findfs with ltv-luks-wrapper"
        print "\tltv-luks-wrapper $cryptopts -p /sbin/mdev ${KOPT_debug_init:+-d} \\"
        print "\t\t${KOPT_usbdelay:+-t $((KOPT_usbdelay*1000))} \\"
        print "\t\t${KOPT_uevent_buf_size:+-U $KOPT_uevent_buf_size} \\"
        print "\t\t\"$KOPT_root\""
        done=1
        next
    }
    { print }
')

# write back
printf '%s\n' "$content" > "$INIT_PATH"
echo "[$INIT_PATH] Patch applied successfully"
