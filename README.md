# Broadcast_TCP

A reliable, encrypted covert transport protocol built in Python with zero external dependencies. It tunnels bidirectional traffic inside the trailer of standard Layer 2 ARP broadcast frames (`ff:ff:ff:ff:ff:ff`), allowing communication even when unicast IP, ICMP, or TCP/UDP traffic is blocked.

## What it does

- **Layer 2 framing (`framing.py`)** – Embeds and extracts transport segments inside ARP frame trailers, supporting both Linux raw sockets (`AF_PACKET`) and an in-memory `SimulatedBroadcastBus` for cross-platform testing.
- **TCP-like reliability (`protocol.py`, `reliability.py`, `session.py`)** – Implements a 3-way handshake, sequence numbers, cumulative ACKs, out-of-order reassembly, CRC-16 checks, and dynamic RTO with exponential backoff.
- **Authenticated encryption (`crypto.py`)** – Encrypt-then-MAC stream cipher using SHA-256 CTR keystream and HMAC-SHA256 integrity checks.

## Quick start

Run the test suite:
```bash
python test_broadcast_tcp.py
```

Run in simulation mode (two terminals):
```bash
# Terminal 1 (Server)
python main.py --role server --mode sim

# Terminal 2 (Client)
python main.py --role client --mode sim
```

Run over a real Layer 2 interface (Linux, requires root):
```bash
sudo python3 main.py --role server --mode raw --interface eth0
```

## Project structure

- `main.py` – CLI entry point for server and client modes
- `framing.py` – ARP trailer encoding/decoding, `RawSocketInterface`, and `SimulatedBroadcastBus`
- `protocol.py` – 20-byte binary header serialization and CRC-16 validation
- `reliability.py` – `RTOCalculator`, `ReassemblyBuffer`, and `Fragmenter`
- `session.py` – Full TCP-style state machine and retransmission loop
- `crypto.py` – SHA-256 CTR encryption and HMAC-SHA256 authentication
- `test_broadcast_tcp.py` – Unit and integration tests
