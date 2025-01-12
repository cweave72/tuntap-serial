"""
Module to perform SLIP encoding.
"""
import queue
import typing as t
import logging

from queue import Queue
from rich.logging import RichHandler

logger = logging.getLogger(__name__)

END = 0xC0
ESC = 0xDB
ESC_END = 0xDC
ESC_ESC = 0xDD


def framer(bytes_in: t.ByteString) -> t.ByteString:
    """Perform SLIP framing on the input byte stream."""
    enc_out = []
    enc_out.append(END)

    for byte in bytes_in:
        if byte == END:
            enc_out.append(ESC)
            enc_out.append(ESC_END)
        elif byte == ESC:
            enc_out.append(ESC)
            enc_out.append(ESC_ESC)
        else:
            enc_out.append(byte)

    enc_out.append(END)
    return bytearray(enc_out)


class Deframer:
    def __init__(self, max_pkt_size=1600):
        self.state = "INIT"
        self.q = Queue()
        self.data = []
        self.max_pkt = max_pkt_size
        self.idx = 0

    def process(self, new_data):
        """Processes new data, returns decoded message if framing detected.
        """
        logger.debug(f"New data: {len(new_data)} bytes (state={self.state})")

        # Push new data into the queue.
        for b in new_data:
            self.q.put_nowait(b)

        while True:

            if self.state == "INIT":
                logger.debug("DEFRAMER: INIT")
                self.data = []
                self.state = "FIND_SOF"

            elif self.state == "FIND_SOF":
                # Read from queue until framing found or empty.
                while True:
                    try:
                        byte = self.q.get_nowait()
                    except queue.Empty:
                        logger.debug("DEFRAMER: FIND_SOF: fifo empty")
                        self.state = "INIT"
                        return None
                    except Exception as e:
                        logger.error(f"{str(e)}")
                        self.state = "INIT"
                        return None

                    if byte == END:
                        logger.debug("DEFRAMER: FIND_SOF: Found framing.")
                        self.state = "FIND_EOF"
                        break

            elif self.state == "FIND_EOF":
                get_escaped = False
                while True:
                    if len(self.data) == self.max_pkt:
                        logger.error("DEFRAMER: FIND_EOF: Max packet size reached.")
                        self.state = "INIT"
                        return None

                    try:
                        byte = self.q.get_nowait()
                    except queue.Empty:
                        logger.debug("DEFRAMER: FIND_EOF: fifo empty")
                        return None
                    except Exception as e:
                        logger.error(f"{str(e)}")
                        self.state = "INIT"
                        return None

                    if byte == END:
                        logger.debug(f"DEFRAMER: FIND_EOF: Found framing (len={len(self.data)}).")
                        self.state = "INIT"
                        return bytearray(self.data)
                    elif byte == ESC:
                        get_escaped = True
                        continue
                    elif byte == ESC_ESC and get_escaped:
                        self.data.append(ESC)
                    elif byte == ESC_END and get_escaped:
                        self.data.append(END)
                    else:
                        self.data.append(byte)

                    get_escaped = False

            else:
                self.state = "INIT"
                return None
