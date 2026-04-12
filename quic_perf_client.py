import asyncio
import argparse
import time
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

class PerfClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = asyncio.Event()
        self.data = b""
        self.flow_id = 0

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            cid = self._quic.host_cid.hex()
            print(f"  Flow {self.flow_id}: connected (CID: {cid})")
        if isinstance(event, StreamDataReceived):
            self.data += event.data
            if event.end_stream:
                self.received.set()

async def run_single_flow(host, port, config, flow_id, data_size, duration):
    async with connect(host, port, configuration=config,
                       create_protocol=PerfClientProtocol) as protocol:
        protocol.flow_id = flow_id
        stream_id = protocol._quic.get_next_available_stream_id()

        if duration > 0:
            # Time-based transfer
            start = time.time()
            total_sent = 0
            chunk = b"x" * 65536
            while time.time() - start < duration:
                protocol._quic.send_stream_data(stream_id, chunk, end_stream=False)
                protocol.transmit()
                total_sent += len(chunk)
                await asyncio.sleep(0.001)
            protocol._quic.send_stream_data(stream_id, b"", end_stream=True)
            protocol.transmit()
            elapsed = time.time() - start
        else:
            # Size-based transfer
            payload = b"x" * data_size
            start = time.time()
            protocol._quic.send_stream_data(stream_id, payload, end_stream=True)
            protocol.transmit()
            total_sent = data_size
            elapsed = None

        try:
            await asyncio.wait_for(protocol.received.wait(), timeout=30)
            if elapsed is None:
                elapsed = time.time() - start
        except asyncio.TimeoutError:
            elapsed = time.time() - start
            print(f"  Flow {flow_id}: timeout after {elapsed:.2f}s")
            return flow_id, total_sent, elapsed

        throughput_mbps = (total_sent * 8) / (elapsed * 1_000_000)
        print(f"  Flow {flow_id}: {total_sent/1_000_000:.2f} MB in "
              f"{elapsed:.3f}s ({throughput_mbps:.2f} Mbps)")
        return flow_id, total_sent, elapsed

async def main():
    parser = argparse.ArgumentParser(description="QUIC Performance Client")
    parser.add_argument("host", help="Server address")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-P", "--parallel", type=int, default=1,
                        help="Number of parallel flows")
    parser.add_argument("-n", "--bytes", type=int, default=10_000_000,
                        help="Bytes to send per flow")
    parser.add_argument("-t", "--time", type=int, default=0,
                        help="Duration in seconds (overrides -n)")
    parser.add_argument("--cid-length", type=int, default=20)
    args = parser.parse_args()

    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE
    config.connection_id_length = args.cid_length
    config.alpn_protocols = ["perf"]

    print(f"Connecting to {args.host}:{args.port} "
          f"({args.parallel} parallel flows, CID length: {args.cid_length})")
    print("-" * 60)

    tasks = []
    for i in range(args.parallel):
        tasks.append(run_single_flow(
            args.host, args.port, config, i,
            args.bytes, args.time))

    results = await asyncio.gather(*tasks)

    print("-" * 60)
    total_bytes = sum(r[1] for r in results)
    max_time = max(r[2] for r in results)
    agg_throughput = (total_bytes * 8) / (max_time * 1_000_000)
    print(f"Summary: {len(results)} flows, "
          f"{total_bytes/1_000_000:.2f} MB total, "
          f"{agg_throughput:.2f} Mbps aggregate")

asyncio.run(main())
