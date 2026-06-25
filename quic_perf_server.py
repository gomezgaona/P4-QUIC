import asyncio
import argparse
import time
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

STATS_MAGIC = b"STATS"


class PerfServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Per-stream accumulators: stream_id → bytes_received
        self._stream_bytes: dict = {}
        self._stream_start: dict = {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print(f"[{time.strftime('%H:%M:%S')}] connected  "
                  f"DCID={self._quic.host_cid.hex()}", flush=True)

        if isinstance(event, StreamDataReceived):
            sid = event.stream_id

            # Stats request: client sends STATS_MAGIC on a dedicated control
            # stream.  Respond with the byte count of whichever data stream has
            # accumulated the most bytes so far.
            if event.data == STATS_MAGIC and event.end_stream:
                if self._stream_bytes:
                    data_sid = max(self._stream_bytes,
                                   key=self._stream_bytes.get)
                    total   = self._stream_bytes[data_sid]
                    elapsed = (time.perf_counter()
                                - self._stream_start[data_sid])
                    mbps    = ((total * 8) / (elapsed * 1_000_000)
                               if elapsed > 0 else 0.0)
                    print(f"[{time.strftime('%H:%M:%S')}] stream {data_sid}: "
                          f"{total/1e6:.2f} MB in {elapsed:.3f}s"
                          f"  ({mbps:.2f} Mbps)", flush=True)
                else:
                    total = 0
                self._quic.send_stream_data(sid, str(total).encode(),
                                            end_stream=True)
                self.transmit()
                return

            # Regular data — accumulate bytes.
            if sid not in self._stream_bytes:
                self._stream_bytes[sid] = 0
                self._stream_start[sid] = time.perf_counter()

            self._stream_bytes[sid] += len(event.data)


async def main():
    parser = argparse.ArgumentParser(description="QUIC Performance Server")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("--cid-length", type=int, default=20)
    parser.add_argument("--cert", default="quic_cert.pem")
    parser.add_argument("--key", default="quic_key.pem")
    args = parser.parse_args()

    config = QuicConfiguration(is_client=False)
    config.load_cert_chain(args.cert, args.key)
    config.connection_id_length = args.cid_length
    config.alpn_protocols = ["perf"]
    config.max_data = 64 * 1024 * 1024
    config.max_stream_data_bidi_local  = 64 * 1024 * 1024
    config.max_stream_data_bidi_remote = 64 * 1024 * 1024
    config.max_stream_data_uni         = 64 * 1024 * 1024

    print(f"QUIC perf server  port={args.port}  CID={args.cid_length}B",
          flush=True)
    await serve("0.0.0.0", args.port, configuration=config,
                create_protocol=PerfServerProtocol)
    await asyncio.Future()


asyncio.run(main())
