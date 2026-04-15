import asyncio
import argparse
import binascii
import time
import ssl
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import StreamDataReceived, HandshakeCompleted

CHUNK = 65536       # bytes per send call
STATS_MAGIC = b"STATS"


def cid_to_bucket(cid_hex: str) -> int:
    """Approximate the P4 register index for a given CID.

    The dataplane computes Hash<bit<17>>(CRC32) over the 20-byte DCID and uses
    the result as the register index.  Python's binascii.crc32 uses the same
    ISO-HDLC polynomial, so the lower 17 bits match in practice.
    """
    return binascii.crc32(bytes.fromhex(cid_hex)) & 0x1FFFF


class PerfClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = asyncio.Event()
        self.server_total = 0    # bytes reported by the server
        self._server_buf = b""   # accumulate server response across chunks
        self._stats_stream_id = None  # set just before sending STATS request
        self.flow_id = 0

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            cid = self._quic.host_cid.hex()
            bucket = cid_to_bucket(cid)
            print(f"  Flow {self.flow_id}: connected  "
                  f"CID={cid}  bucket=0x{bucket:05x}")
        if isinstance(event, StreamDataReceived):
            # Only process the stats-reply stream; ignore the data stream.
            if event.stream_id != self._stats_stream_id:
                return
            self._server_buf += event.data
            if event.end_stream:
                try:
                    self.server_total = int(self._server_buf)
                except ValueError:
                    self.server_total = 0
                self.received.set()


async def run_single_flow(host, port, config, flow_id,
                          data_size, duration, interval):
    async with connect(host, port, configuration=config,
                       create_protocol=PerfClientProtocol) as protocol:
        protocol.flow_id = flow_id
        data_sid  = protocol._quic.get_next_available_stream_id()
        chunk = b"x" * CHUNK

        start = time.perf_counter()
        total_sent = 0

        # Mutable cells shared with the reporter coroutine.
        interval_bytes = [0]
        interval_start = [start]

        async def reporter():
            next_deadline = start + interval
            while True:
                wait = max(0.0, next_deadline - time.perf_counter())
                await asyncio.sleep(wait)
                now = time.perf_counter()
                dt = now - interval_start[0]
                mbps = (interval_bytes[0] * 8) / (dt * 1_000_000) if dt > 0 else 0.0
                print(f"  Flow {flow_id} [{now - start:5.1f}s]  {mbps:8.2f} Mbps (queued)")
                interval_bytes[0] = 0
                interval_start[0] = now
                # Always schedule from now to avoid short catch-up windows.
                next_deadline = now + interval

        reporter_task = asyncio.create_task(reporter()) if interval > 0 else None

        try:
            if duration > 0:
                # Time-based: send chunks until the deadline.
                # Do NOT set end_stream here — use the STATS control stream instead.
                deadline = start + duration
                while time.perf_counter() < deadline:
                    protocol._quic.send_stream_data(data_sid, chunk,
                                                    end_stream=False)
                    protocol.transmit()
                    total_sent += CHUNK
                    interval_bytes[0] += CHUNK
                    await asyncio.sleep(0.001)
            else:
                # Size-based: send in CHUNK-sized pieces (no end_stream).
                remaining = data_size
                while remaining > 0:
                    n = min(CHUNK, remaining)
                    remaining -= n
                    protocol._quic.send_stream_data(data_sid, chunk[:n],
                                                    end_stream=False)
                    protocol.transmit()
                    total_sent += n
                    interval_bytes[0] += n
                    await asyncio.sleep(0.001)
        finally:
            if reporter_task:
                reporter_task.cancel()

        # Capture send-phase elapsed before the stats round-trip.
        elapsed = time.perf_counter() - start

        # Open a fresh control stream to ask the server for its byte count.
        # This avoids relying on stream FIN delivery, which can be delayed
        # when aioquic's send buffer is still draining.
        stats_sid = protocol._quic.get_next_available_stream_id()
        protocol._stats_stream_id = stats_sid
        protocol._quic.send_stream_data(stats_sid, STATS_MAGIC, end_stream=True)
        protocol.transmit()

        try:
            await asyncio.wait_for(protocol.received.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass

        # Use server byte count for throughput when available — it is the
        # ground truth.  Client total_sent counts bytes queued into aioquic's
        # send buffer, which can exceed bytes actually delivered on the wire.
        if protocol.server_total:
            mbps = (protocol.server_total * 8) / (elapsed * 1_000_000)
            print(f"  Flow {flow_id}: {protocol.server_total/1e6:.2f} MB "
                  f"delivered in {elapsed:.3f}s  ({mbps:.2f} Mbps)  "
                  f"[queued {total_sent/1e6:.2f} MB]")
        else:
            mbps = (total_sent * 8) / (elapsed * 1_000_000)
            print(f"  Flow {flow_id}: {total_sent/1e6:.2f} MB queued in "
                  f"{elapsed:.3f}s  ({mbps:.2f} Mbps)  "
                  f"server_rx=n/a (check server log)")
        delivered = protocol.server_total if protocol.server_total else total_sent
        return flow_id, delivered, elapsed


async def main():
    parser = argparse.ArgumentParser(description="QUIC Performance Client")
    parser.add_argument("host", help="Server address")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-P", "--parallel", type=int, default=1,
                        help="Number of parallel flows")
    parser.add_argument("-n", "--bytes", type=int, default=10_000_000,
                        help="Bytes to send per flow (size-based mode)")
    parser.add_argument("-t", "--time", type=int, default=0,
                        help="Duration in seconds (overrides -n)")
    parser.add_argument("-i", "--interval", type=float, default=0,
                        help="Per-flow reporting interval in seconds (0 = off)")
    parser.add_argument("--cid-length", type=int, default=20)
    args = parser.parse_args()

    config = QuicConfiguration(is_client=True)
    config.verify_mode = ssl.CERT_NONE
    config.connection_id_length = args.cid_length
    config.alpn_protocols = ["perf"]
    # Increase flow-control windows so aioquic keeps enough data in flight.
    # Default is 1 MB which caps throughput to ~BDP at typical LAN RTTs.
    config.max_data = 64 * 1024 * 1024
    config.max_stream_data_bidi_local  = 64 * 1024 * 1024
    config.max_stream_data_bidi_remote = 64 * 1024 * 1024
    config.max_stream_data_uni         = 64 * 1024 * 1024

    mode = f"{args.time}s" if args.time > 0 else f"{args.bytes/1e6:.1f} MB"
    print(f"Connecting to {args.host}:{args.port}  —  "
          f"{args.parallel} flow(s), {mode}, CID={args.cid_length}B")
    if args.interval > 0:
        print(f"Interval reporting every {args.interval}s")
    print("-" * 60)

    tasks = [
        run_single_flow(args.host, args.port, config, i,
                        args.bytes, args.time, args.interval)
        for i in range(args.parallel)
    ]
    results = await asyncio.gather(*tasks)

    print("-" * 60)
    total_bytes = sum(r[1] for r in results)
    max_time    = max(r[2] for r in results)
    agg_mbps    = (total_bytes * 8) / (max_time * 1_000_000)
    print(f"Total: {len(results)} flow(s)  "
          f"{total_bytes/1e6:.2f} MB delivered  "
          f"{agg_mbps:.2f} Mbps aggregate")


asyncio.run(main())
