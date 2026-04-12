import asyncio
import argparse
import time
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

class PerfServerProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print(f"[{time.strftime('%H:%M:%S')}] New connection from client "
                  f"(DCID: {self._quic.host_cid.hex()})")
        if isinstance(event, StreamDataReceived):
            data_len = len(event.data)
            if event.end_stream:
                # Send back a small ACK with byte count
                report = f"{data_len}".encode()
                self._quic.send_stream_data(event.stream_id, report, end_stream=True)
                self.transmit()

async def main():
    parser = argparse.ArgumentParser(description="QUIC Performance Server")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("--cid-length", type=int, default=20)
    parser.add_argument("--cert", default="/tmp/quic_cert.pem")
    parser.add_argument("--key", default="/tmp/quic_key.pem")
    args = parser.parse_args()

    config = QuicConfiguration(is_client=False)
    config.load_cert_chain(args.cert, args.key)
    config.connection_id_length = args.cid_length
    config.alpn_protocols = ["perf"]

    await serve("0.0.0.0", args.port, configuration=config,
                create_protocol=PerfServerProtocol)
    print(f"QUIC perf server running on port {args.port} "
          f"(CID length: {args.cid_length})")
    await asyncio.Future()

asyncio.run(main())
