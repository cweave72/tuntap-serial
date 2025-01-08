# tuntap tool

This tool provides network interface over a standard serial device. This was
written to test Ethernet over serial interfaces using hardware running the
Zephyr RTOS.

Currently, this interface uses the Consistent Overhead Byte Stuffing (COBS)
framing on the serial interface (using \x00 as the frame delimeter).  Hardware
connected must also support this for this to work.

## Getting started

Clone:
`git clone https:`

Run uv:
```bash
cd tuntap
uv sync
```

## Running the tool

Usage:
```
source .venv/bin/activate
(tuntap-demo) sudo .venv/bin/taptool --help
Usage: taptool [OPTIONS] COMMAND [ARGS]...

  CLI receiving raw ethernet frames from tuntap interface.

Options:
  --loglevel TEXT  Debug logging level.
  --logtree        Show logging tree and exit.
  -d, --debug      Shortcut for --loglevel=debug.
  -h, --help       Show this message and exit.

Commands:
  tap   Implements tap device over serial.
  test  Tests tty data.
```

Assumptions:
Serial device to hardware: `/dev/ttyUSB1`
IP address to set on the TAP interface: 192.0.2.2
Note: Hardware device must be on the 192.0.2.0/24 network

Run:
```
(tuntap-demo) sudo .venv/bin/taptool -d tap --tty /dev/ttyUSB1 --ip 192.0.2.2
```

Note we need to run the tool as root since we are using the pytun package.

## Notes on manually creating the TAP device

Creating a tuntap device:
`sudo ip tuntap add mode tap tap0`
Bring it up:
`sudo ip link set dev tap0 up`
Assign IP (example addr shown):
`sudo ip addr add 192.168.40.1/24 dev tap0`

Note: This might bring down your internet connection if your DNS is set to your
local gateway (error is DNS_PROBE_FINISHED_BAD_CONFIG). Fix by adding
nameservers to /etc/netplan (1.1.1.1, 1.0.0.1)

Removing the tap interface:
`sudo tuntap del dev tap0`
