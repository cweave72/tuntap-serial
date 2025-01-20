import sys
import os
import signal
import logging
import select
import click
import random
import time
import shlex
import subprocess
from serial import Serial
from threading import Thread, Event
from pytun import TapTunnel
from scapy.layers.l2 import Ether
from rich.logging import RichHandler
from rich import inspect

import tuntap.slip as slip
import tuntap.cobs as cobs
from tuntap.cobs import Deframer as CobsDeframer
from tuntap.slip import Deframer as SlipDeframer

logger = logging.getLogger()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


loglevels = {
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

threads = []


def signal_handler(sig, frame):
    kill_threads()


def start_threads():
    for t in threads:
        t.start()


def kill_threads():
    for t in threads:
        t.stop()


def wait_threads():
    for t in threads:
        t.join()


def get_params(**kwargs):
    """Converts kwargs to Params class."""

    class Params:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    return Params(**kwargs)


def get_ethertype(typ):
    ether_types = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x0835: "RARP",
        0x086DD: "IPv6",
    }
    return ether_types.get(int(typ), "Other")


def bytes2hex(buf):
    a = [f"{b:02x}" for b in buf]
    return ", ".join(a)


def cobs_frame(bytes_in):
    """Returns a framed message with COBS encoding."""
    enc = cobs.encode(bytes_in)
    return b"\x00" + enc + b"\x00"


class StoppableThread(Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_event = Event()

    def stop(self):
        """Triggers a stop event."""
        self.stop_event.set()

    def stopped(self):
        """Returns True if the thread has been told to stop."""
        return self.stop_event.is_set()


class SerialToEth(StoppableThread):
    def __init__(self, tun, ser, deframer_type, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tun = tun
        self.ser = ser
        if deframer_type == "cobs":
            self.deframer = CobsDeframer().process
        elif deframer_type == "slip":
            self.deframer = SlipDeframer().process
        else:
            logger.error(f"Unsupported deframer: {deframer_type}")
            sys.exit(1)

    def run(self):
        while True:
            if self.stopped():
                logger.debug("Stopping SerialToEth.")
                return

            try:
                raw_bytes = self.ser.read(64)
            except Exception as e:
                logger.warning(f"Broken connection: {str(e)}")
                return

            if len(raw_bytes) == 0:
                continue

            # logger.debug(f"raw_bytes={bytes2hex(raw_bytes)}")
            msg = self.deframer(raw_bytes)
            if msg is not None:
                if len(msg) == 0:
                    logger.warning("Zero length message received.")
                    continue

                pkt = Ether(msg)

                logger.debug(
                    f"==> inb:  {len(msg):4} bytes: "
                    f"src={pkt.src} "
                    f"dst={pkt.dst} "
                    f"type={get_ethertype(pkt.type)} (0x{int(pkt.type):04x})"
                )

                os.write(self.tun.fd, msg)


class EthToSerial(StoppableThread):
    def __init__(self, tun, ser, framer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tun = tun
        self.ser = ser
        self.framer = framer

    def run(self):
        while True:
            # Not using tun.recv() so we can use a timeout.
            readable, _, _ = select.select([self.tun.fd], [], [], 1.0)

            if self.stopped():
                logger.debug("Stopping EthToSerial.")
                return

            if not readable:
                continue

            buf = os.read(self.tun.fd, 1600)
            pkt = Ether(buf)
            logger.debug(
                f"<== outb: {len(buf):4} bytes: "
                f"src={pkt.src} "
                f"dst={pkt.dst} "
                f"type={get_ethertype(pkt.type)} (0x{int(pkt.type):04x})"
            )
            # logger.debug(f"Raw={bytes2hex(buf)}")

            if self.ser is not None:
                if self.framer is not None:
                    data = self.framer(buf)
                    # logger.debug(f"Encoded={bytes2hex(data)}")
                else:
                    data = buf
                try:
                    self.ser.write(data)
                except Exception as e:
                    logger.warning(f"Broken connection: {str(e)}")
                    return


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option("--loglevel", default="info", help="Debug logging level.")
@click.option("--logtree", is_flag=True, help="Show logging tree and exit.")
@click.option("--cobslog", is_flag=True, help="Show cobs logging.")
@click.option("--sliplog", is_flag=True, help="Show slip logging.")
@click.option(
    "-d", "--debug", is_flag=True, help="Shortcut for --loglevel=debug."
)
@click.pass_context
def cli(ctx, **kwargs):
    """CLI providing network interface over serial using a tap interface."""
    global threads

    params = get_params(**kwargs)

    ctx.obj["cli_params"] = params

    if params.debug:
        logger.setLevel(loglevels.get("debug"))
    else:
        logger.setLevel(loglevels.get(params.loglevel, "logging.INFO"))

    ch = RichHandler(rich_tracebacks=True, show_time=False)
    logger.addHandler(ch)

    cobs_logger = logging.getLogger("tuntap.cobs")
    slip_logger = logging.getLogger("tuntap.slip")
    cobs_logger.propagate = params.cobslog
    slip_logger.propagate = params.sliplog

    if params.logtree:
        import logging_tree

        logging_tree.printout()
        sys.exit(0)


@cli.command()
@click.option("--ip", type=str, required=True, help="Device IP address.")
@click.option("--tty", type=str, help="Serial port to bridge to.")
@click.option(
    "--cobs",
    is_flag=True,
    help="Use COBS enccoding over serial port.",
)
@click.option(
    "--slip",
    is_flag=True,
    help="Use SLIP enccoding over serial port.",
)
@click.pass_context
def tap(ctx, **kwargs):
    """Implements tap device over serial."""
    params = get_params(**kwargs)
    cli_params = ctx.obj["cli_params"]

    signal.signal(signal.SIGINT, signal_handler)

    # Bug in pytun.Tunnel initializer requires setting auto_open explicitly to
    # False if you don't want it to auto open the device. Setting no_pi to True
    # prevents the 4-byte protocol header from being applied so we receive raw
    # ethernet frames (IFF_NO_PI setting).
    try:
        tun = TapTunnel(auto_open=False, no_pi=True)
        tun.open()
        tun.set_ipv4(params.ip)
    except Exception as e:
        logger.error(f"Error creating TUNTAP device: {str(e)}")
        return

    ser = None
    if params.tty:
        try:
            ser = Serial(port=params.tty, baudrate=115200, timeout=0.1)
            logger.debug(f"Opened port {params.tty}")
        except Exception as e:
            logger.error(f"Error opening serial port {params.tty}: {str(e)}")
            tun.close()
            return

    framer = None
    if params.slip:
        framer = slip.framer
        deframer_type = "slip"
    elif params.cobs:
        framer = cobs_frame
        deframer_type = "cobs"

    tx = EthToSerial(tun, ser, framer)
    rx = SerialToEth(tun, ser, deframer_type)

    threads.append(tx)
    threads.append(rx)

    start_threads()
    wait_threads()

    # Cleanup after thread ends.
    tun.close()
    if ser is not None:
        ser.close()
        logger.debug(f"Closed port {params.tty}")


@cli.command()
@click.option("--tty", type=str, required=True, help="Serial port to use.")
@click.option(
    "--cobs", is_flag=True, help="Use COBS enccoding over serial port."
)
@click.option(
    "--slip",
    is_flag=True,
    help="Use COBS enccoding over serial port.",
)
@click.option(
    "-n", "--num", type=int, default=16, help="Number of bytes to send."
)
@click.option(
    "-i", "--iter", type=int, default=1, help="Number of packets to send."
)
@click.pass_context
def test(ctx, **kwargs):
    """Tests tty data."""
    params = get_params(**kwargs)
    cli_params = ctx.obj["cli_params"]

    try:
        ser = Serial(port=params.tty, baudrate=115200, timeout=1)
        logger.debug(f"Opened port {params.tty}")
    except Exception as e:
        logger.error(f"Error opening serial port {params.tty}: {str(e)}")
        return

    if params.cobs:
        for k in range(params.iter):
            data = bytearray([x % 256 for x in range(params.num)])

            data = cobs_frame(data)
            logger.debug(f"Encoded={bytes2hex(data)}")

            ser.write(data)
    else:
        deframer = SlipDeframer()
        for k in range(100):
            data = [random.randint(0, 255) for r in range(1500)]
            txdata = slip.framer(data)
            rxdata = deframer.process(txdata)
            if rxdata:
                for i, (d, r) in enumerate(zip(data, rxdata)):
                    if d != r:
                        logger.error(f"[{i}]: 0x{d:02x} != 0x{r:02x}")
                        logger.error(f"encoded={bytes2hex(txdata)}")
                        sys.exit(0)
            else:
                logger.error(f"Error on decode (iter={k}).")
            # logger.debug(f"Encoded({len(data)})={bytes2hex(data)}")
            # ser.write(data)

    ser.close()


def entrypoint():
    cli(obj={})


if __name__ == "__main__":
    entrypoint()
