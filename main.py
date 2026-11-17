import sys
import time
import argparse
from framing import SimulatedBroadcastBus, RawSocketInterface
from session import ReliableTransportSession
from crypto import CryptoEngine

def run_server(mode: str, channel: str, iface: str, key_str: str) -> None:
    crypto = CryptoEngine(key_str.encode("utf-8"))
    if mode == "sim":
        net_iface = SimulatedBroadcastBus(channel_id=channel, node_id="server")
    else:
        net_iface = RawSocketInterface(interface_name=iface)

    session = ReliableTransportSession(net_iface)
    
    def on_event(event_type: str, pkt, pending_chunks: int = 0):
        if event_type == "HANDSHAKE_SYN":
            print(f"\n[+] Incoming connection request | Session ID: {pkt.session_id} | Client ISN: {pkt.seq_num}")
        elif event_type == "DATA_PACKET":
            print(f"    --> [RX PACKET] Seq: {pkt.seq_num} | Size: {len(pkt.payload)}B | Pending in reassembly buffer: {pending_chunks}")

    session.on_packet_event = on_event
    session.listen()

    print(f"[*] Broadcast TCP Server active on channel '{channel}' ({mode} mode)")
    print("[*] Waiting for incoming client connections...\n")

    msg_count = 0
    try:
        while True:
            data = session.recv(timeout=0.5)
            if data:
                msg_count += 1
                try:
                    decrypted = crypto.decrypt(data)
                    msg_text = decrypted.decode("utf-8", errors="replace")
                    print("\n" + "=" * 55)
                    print(f" [MESSAGE #{msg_count} RECEIVED & DECRYPTED]")
                    print(f" Payload Size: {len(data)} bytes (Encrypted+Authenticated)")
                    print(f" Content:      \"{msg_text}\"")
                    print(f" Session Stats: Total Packets RX: {session.stats['rx_packets']} | TX: {session.stats['tx_packets']}")
                    print("=" * 55 + "\n")
                    
                    response = f"ACK #{msg_count}: {msg_text}"
                    encrypted_resp = crypto.encrypt(response.encode("utf-8"))
                    session.send(encrypted_resp)
                except Exception as err:
                    print(f"[!] Decryption error: {err}")
            time.sleep(0.01)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
        net_iface.close()

def run_client(mode: str, channel: str, iface: str, key_str: str) -> None:
    crypto = CryptoEngine(key_str.encode("utf-8"))
    if mode == "sim":
        net_iface = SimulatedBroadcastBus(channel_id=channel, node_id="client")
    else:
        net_iface = RawSocketInterface(interface_name=iface)

    session = ReliableTransportSession(net_iface)
    if not session.connect(timeout=5.0):
        print("[FAIL] Connection establishment failed.")
        net_iface.close()
        return

    print("[SUCCESS] Handshake complete. Session established.")
    try:
        while True:
            text = input("Message to send (or 'exit'): ")
            if text.strip().lower() == "exit":
                break
            if not text.strip():
                continue
            encrypted = crypto.encrypt(text.encode("utf-8"))
            session.send(encrypted)
            resp_bytes = session.recv(timeout=2.0)
            if resp_bytes:
                try:
                    decrypted = crypto.decrypt(resp_bytes)
                    print(f"[RESPONSE] {decrypted.decode('utf-8', errors='replace')}")
                except Exception as err:
                    print(f"[ERROR] Response decryption error: {err}")
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
        net_iface.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["server", "client"], required=True)
    parser.add_argument("--mode", choices=["sim", "raw"], default="sim")
    parser.add_argument("--channel", default="broadcast_channel_1")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--key", default="AVIEL_SECRET_KEY_2026")
    args = parser.parse_args()

    if args.role == "server":
        run_server(args.mode, args.channel, args.interface, args.key)
    else:
        run_client(args.mode, args.channel, args.interface, args.key)

if __name__ == "__main__":
    main()
