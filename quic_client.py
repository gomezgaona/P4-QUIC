import asyncio
import time
import ssl
import argparse
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

CHUNK_SIZE = 65536  # 64 KB per send call — keeps memory flat regardless of total size

def parse_size(s):
    """Parse a human-readable size string into bytes.  Examples: 100MB, 1GB, 500KB."""
    s = s.strip().upper()
    for suffix, mult in [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10), ("B", 1)]:
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * mult)
    return int(s)

class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.done = asyncio.Event()
        self._conn_id = 0

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            print(f"[conn {self._conn_id}] Handshake complete")
        if isinstance(event, StreamDataReceived) and event.end_stream:
            self.done.set()

async def run_client(host, port, data_size, conn_id):
    config = QuicConfiguration(is_client=True)
    config.connection_id_length = 20   # match switch's 20-byte speculative DCID extract
    config.verify_mode = ssl.CERT_NONE
    config.alpn_protocols = ["sink"]

    async with connect(host, port, configuration=config, create_protocol=ClientProtocol) as protocol:
        protocol._conn_id = conn_id
        stream_id = protocol._quic.get_next_available_stream_id()
        chunk = b"x" * CHUNK_SIZE

        sent = 0
        start = time.time()
        last_report = start

        while sent < data_size:
            to_send = min(CHUNK_SIZE, data_size - sent)
            end_stream = (sent + to_send >= data_size)
            protocol._quic.send_stream_data(stream_id, chunk[:to_send], end_stream=end_stream)
            protocol.transmit()
            sent += to_send

            # Yield to the event loop so aioquic can process ACKs and advance
            # the flow-control window; without this the send buffer fills and stalls.
            await asyncio.sleep(0)

            now = time.time()
            if now - last_report >= 5.0:
                rate = sent / (now - start) / (1 << 20)
                print(f"[conn {conn_id}]  {sent/(1<<20):.1f} / {data_size/(1<<20):.1f} MB  ({rate:.1f} MB/s)")
                last_report = now

        # Wait for the server's end-of-stream acknowledgement
        elapsed_send = time.time() - start
        print(f"[conn {conn_id}] All data sent ({data_size/(1<<20):.1f} MB in {elapsed_send:.1f}s), waiting for server ACK...")
        try:
            await asyncio.wait_for(protocol.done.wait(), timeout=30)
            elapsed = time.time() - start
            print(f"[conn {conn_id}] Done — {data_size/(1<<20):.1f} MB in {elapsed:.1f}s "
                  f"({data_size/elapsed/(1<<20):.1f} MB/s)")
        except asyncio.TimeoutError:
            print(f"[conn {conn_id}] Timeout waiting for server ACK")

async def main(host, port, num_connections, data_size):
    print(f"Starting {num_connections} simultaneous QUIC connection(s) to {host}:{port}")
    print(f"Payload per connection: {data_size/(1<<20):.1f} MB  |  total: {num_connections*data_size/(1<<20):.1f} MB")
    print("-" * 60)
    await asyncio.gather(*[
        run_client(host, port, data_size, conn_id=i + 1)
        for i in range(num_connections)
    ])
    print("-" * 60)
    print("All connections finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC sink client")
    parser.add_argument("--host", default="192.168.0.2")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--connections", type=int, default=1,
                        help="Number of simultaneous QUIC connections (default: 1)")
    parser.add_argument("--data-size", default="100MB",
                        help="Data to send per connection, e.g. 100MB, 1GB, 100GB (default: 100MB)")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.connections, parse_size(args.data_size)))
