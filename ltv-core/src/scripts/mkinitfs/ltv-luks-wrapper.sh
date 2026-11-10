#!/bin/sh
# ltv-luks-wrapper: controlled nlplug-findfs with dual unlock path
# Replaces direct nlplug-findfs call in initramfs-init
# Usage: ltv-luks-wrapper [nlplug-findfs args including -c -m -k ...]

set -eu

# Original args passed from init script (includes crypto options)
CRYPTOPTS="$@"

# Extract non-crypto args for second nlplug-findfs pass (udev settling)
# Strip: -c DEVICE, -m NAME, -k KEY, -H HEADER, -o OFFSET, -D
NON_CRYPTOPTS=$(echo "$CRYPTOPTS" | sed \
  -e 's/-c [^ ]*//g' \
  -e 's/-m [^ ]*//g' \
  -e 's/-k [^ ]*//g' \
  -e 's/-H [^ ]*//g' \
  -e 's/-o [^ ]*//g' \
  -e 's/-D//g')

# LTV_MAPPERS from staged metadata (written by admin during unlock)
# Falls back to kernel cmdline if staging not yet done
get_mappers() {
  if [ -d /run/ltv ] && [ -n "$(ls -A /run/ltv 2>/dev/null)" ]; then
    for f in /run/ltv/*/mapper; do
      [ -f "$f" ] && cat "$f"
    done | sort -u
  else
    # Fallback: read from kernel cmdline via KOPT_ltv_mappers
    # (set by init script before calling wrapper)
    echo "$LTV_MAPPERS" | tr ',' '\n'
  fi
}

# Start nlplug-findfs WITH crypto options in BACKGROUND (TTY fallback path)
nlplug-findfs $CRYPTOPTS -p /sbin/mdev -d &
NLPID=$!

# Start dropbear SSH server
dropbear -E -p ${LTV_PORT:-22} -r /etc/mkinitfs/ltv-stuff/etc/dropbear/dropbear_ed25519_host_key -D /etc/mkinitfs/ltv-stuff/root/.ssh/ &
DROPBEAR_PID=$!

# Monitor loop: wait for admin to write /run/ltv/resume OR all mappers to appear
ELAPSED=0
while true; do
  # Check if admin signaled completion
  if [ -e /run/ltv/resume ]; then
    break
  fi

  # Check if ALL expected mappers exist (TTY manual unlock path)
  ready=1
  for m in $(get_mappers); do
    [ -e /dev/mapper/$m ] || ready=0
  done
  [ $ready -eq 1 ] && break

  # Check if background nlplug-findfs exited (TTY success or error)
  if ! kill -0 $NLPID 2>/dev/null; then
    wait $NLPID
    exit $?
  fi

  sleep 1
  ELAPSED=$((ELAPSED + 1))
  if [ $ELAPSED -gt 300 ]; then
    kill -9 $NLPID $DROPBEAR_PID 2>/dev/null
    exit 1
  fi
done

# Admin signaled done (or TTY succeeded) - kill crypto nlplug-findfs
kill -9 $NLPID 2>/dev/null
wait $NLPID 2>/dev/null

# Restart nlplug-findfs WITHOUT crypto to finish udev for remaining devices
nlplug-findfs $NON_CRYPTOPTS -p /sbin/mdev -d

# Clean up dropbear
kill $DROPBEAR_PID 2>/dev/null
wait $DROPBEAR_PID 2>/dev/null

exit 0
