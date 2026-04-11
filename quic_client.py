import asyncio
import time
import ssl
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
            print(f"Handshake complete! ALPN: {event.alpn_protocol}")
        if isinstance(event, StreamDataReceived):
            self.data += event.data
            print(f"Received {len(event.data)} bytes (total: {len(self.data)})")
            if event.end_stream:
                self.received.set()

async def run_client(host, port, data_size=100000):
    config = QuicConfiguration(is_client=True)
    config.connection_id_length = 20
    config.verify_mode = ssl.CERT_NONE
    config.alpn_protocols = ["echo"]

    async with connect(host, port, configuration=config, create_protocol=ClientProtocol) as protocol:
        print("Connected! Sending data...")
        stream_id = protocol._quic.get_next_available_stream_id()
        payload = b"x" * data_size
        start = time.time()
        protocol._quic.send_stream_data(stream_id, payload, end_stream=True)
        protocol.transmit()
        print(f"Sent {len(payload)} bytes on stream {stream_id}, waiting for echo...")
        try:
            await asyncio.wait_for(protocol.received.wait(), timeout=10)
            elapsed = time.time() - start
            print(f"Success! Received {len(protocol.data)} bytes in {elapsed:.3f}s")
        except asyncio.TimeoutError:
            print("Timeout waiting for response after 10 seconds")

asyncio.run(run_client("192.168.0.2", 443))
