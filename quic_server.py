import asyncio
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived

class EchoProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            # Echo back the data
            self._quic.send_stream_data(event.stream_id, event.data, event.end_stream)
            self.transmit()

async def main():
    config = QuicConfiguration(is_client=False)
    config.load_cert_chain("/tmp/quic_cert.pem", "/tmp/quic_key.pem")
    config.max_datagram_frame_size = 65536
    await serve("0.0.0.0", 4433, configuration=config, create_protocol=EchoProtocol)
    print("QUIC server running on port 4433")
    await asyncio.Future()  # run forever

asyncio.run(main())
