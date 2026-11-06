#!/bin/sh
# ltv-common: shared functions for ltv hooks

getarg() {
    local name="$1" value
    for x in $(cat /proc/cmdline); do
        case $x in
            ${name}=*) value=${x#*=} ;;
        esac
    done
    echo "$value"
}