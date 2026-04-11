import asyncio
import argparse
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived

class SinkProtocol(QuicConnectionProtocol):
    """Sink server: discards received data, sends end-of-stream ACK when the
    client closes the stream.  Avoids buffering or re-transmitting large
    payloads, making it suitable for high-volume throughput experiments."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._received = {}   # stream_id → byte count

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            self._received[sid] = self._received.get(sid, 0) + len(event.data)
            if event.end_stream:
                total = self._received.pop(sid, 0)
                print(f"Stream {sid}: received {total/(1<<20):.2f} MB — sending ACK")
                # Acknowledge with an empty end-of-stream frame
                self._quic.send_stream_data(sid, b"", end_stream=True)
                self.transmit()

async def main(host, port, cert, key):
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain(cert, key)
    config.alpn_protocols = ["sink"]

    print(f"QUIC sink server listening on {host}:{port}")
    await serve(host, port, configuration=config, create_protocol=SinkProtocol)
    await asyncio.Future()  # run forever

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC sink server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", default="/tmp/quic_cert.pem")
    parser.add_argument("--key", default="/tmp/quic_key.pem")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.cert, args.key))
