#!/bin/sh
#
# This script configures socat for networking with QEMU.

# Run socat in a loop. This way we can restart qemu and do not need
# to manually restart socat.

STOPPED=0
trap ctrl_c INT TERM

ctrl_c() {
    STOPPED=1
}

# If this file entry already exists, socat may complain
rm -f /tmp/slip.sock

while [ $STOPPED -eq 0 ]; do
    socat PTY,link=/tmp/slip.dev UNIX-LISTEN:/tmp/slip.sock
done

echo "\nExited socat."
