import asyncio
import time
import ssl
import argparse
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = asyncio.Event()
        self.data = b""

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print(f"[conn {self._conn_id}] Handshake complete! ALPN: {event.alpn_protocol}")
        if isinstance(event, StreamDataReceived):
            self.data += event.data
            if event.end_stream:
                self.received.set()

async def run_client(host, port, data_size, conn_id):
    config = QuicConfiguration(is_client=True)
    config.connection_id_length = 20   # match switch's speculative 20-byte DCID extract
    config.verify_mode = ssl.CERT_NONE
    config.alpn_protocols = ["echo"]

    async with connect(host, port, configuration=config, create_protocol=ClientProtocol) as protocol:
        protocol._conn_id = conn_id
        stream_id = protocol._quic.get_next_available_stream_id()
        payload = b"x" * data_size
        start = time.time()
        protocol._quic.send_stream_data(stream_id, payload, end_stream=True)
        protocol.transmit()
        print(f"[conn {conn_id}] Sent {len(payload)} bytes, waiting for echo...")
        try:
            await asyncio.wait_for(protocol.received.wait(), timeout=15)
            elapsed = time.time() - start
            print(f"[conn {conn_id}] Done — {len(protocol.data)} bytes echoed in {elapsed:.3f}s")
        except asyncio.TimeoutError:
            print(f"[conn {conn_id}] Timeout after 15 s")

async def main(host, port, num_connections, data_size):
    print(f"Starting {num_connections} simultaneous QUIC connection(s) to {host}:{port}")
    print(f"Payload per connection: {data_size} bytes")
    print("-" * 60)
    await asyncio.gather(*[
        run_client(host, port, data_size, conn_id=i+1)
        for i in range(num_connections)
    ])
    print("-" * 60)
    print("All connections finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC echo client")
    parser.add_argument("--host", default="192.168.0.2")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--connections", type=int, default=1,
                        help="Number of simultaneous QUIC connections (default: 1)")
    parser.add_argument("--data-size", type=int, default=100000,
                        help="Payload bytes per connection (default: 100000)")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.connections, args.data_size))
