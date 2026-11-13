#!/bin/sh
# ltv-luks-wrapper: controlled nlplug-findfs with dual unlock path
# Replaces direct nlplug-findfs cryptroot call in initramfs-init
# Usage: ltv-luks-wrapper.sh [nlplug-findfs args including -c -m -k ...]

# 1. filter non crypto arguments
set -- "$@"
# we use a position array via set -- to keep quoting
NON_CRYPTOPTS=""

filter_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            # skip crypto options with arguments
            -c|--crypt-device|-m|--crypt-name|-k|--crypt-key|-H|--crypt-header|-o|--crypt-offset)
                shift 2
                ;;
            # skip crypto options without arguments
            -D|--crypt-discards)
                shift 1
                ;;
            # keep every other options
            *)
                # we add a temporary delimiter '|' as ash has on real arrays
                NON_CRYPTOPTS="${NON_CRYPTOPTS}${NON_CRYPTOPTS:+|}$1"
                shift 1
                ;;
        esac
    done
}

filter_args "$@"

# 2. Start dropbear SSH server so ltv-admin or similar can connect
dropbear -E -p ${LTV_PORT:-22} -r /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key -D /etc/mkinitfs/ltv-stuff/root/.ssh/ &

cleanup() {
    DBPIDS=$(pidof dropbear)
    [ -n "$DBPIDS" ] && kill -9 $DBPIDS 2>/dev/null || true
    kill -9 "$MONITOR_PID" 2>/dev/null || true
}

trap cleanup EXIT

# 3. background monitor for SSH Unlock
(
    while true; do
        if [ -e /run/ltv/resume ]; then
            # Terminate the first nlplug-findfs process that we started earlier
            # -> the original call we wrapped ourselves into.
            # -> now everything is unlocked and the script can continue running
            NLPID=$(pidof nlplug-findfs)
            if [ -n "$NLPID" ]; then
                kill -9 $NLPID 2>/dev/null || true
            fi
            break
        fi
        sleep 1
    done
) &
MONITOR_PID=$!

# 4. First run in the foreground (for TTY password prompt) (original call)
nlplug-findfs "$@" || true

# 5. If unlocked via SSH: Second run without crypto options
if [ -e /run/ltv/resume ]; then
    # loaded filtered arguments into $@
    OLD_IFS="$IFS"
    IFS="|"
    set -- $NON_CRYPTOPTS
    IFS="$OLD_IFS"

    # Second run: triggers mdev/LVM/device events for the open mapper device
    nlplug-findfs "$@"
fi
