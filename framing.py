import os
import time
import socket
import select
import struct
from typing import Optional, Callable
from protocol import Packet

STANDARD_ARP_SIZE = 42

def build_ether_arp_frame(target_ip: str = "10.0.0.122", sender_ip: str = "10.0.0.1", sender_mac: bytes = b"\xaa\xaa\xaa\xaa\xaa\xaa") -> bytes:
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    eth_type = b"\x08\x06"
    ether_header = dst_mac + sender_mac + eth_type
    
    hw_type = b"\x00\x01"
    proto_type = b"\x08\x00"
    hw_size = b"\x06"
    proto_size = b"\x04"
    opcode = b"\x00\x01"
    
    sender_ip_bytes = socket.inet_aton(sender_ip)
    target_mac = b"\x00\x00\x00\x00\x00\x00"
    target_ip_bytes = socket.inet_aton(target_ip)
    
    arp_body = hw_type + proto_type + hw_size + proto_size + opcode + sender_mac + sender_ip_bytes + target_mac + target_ip_bytes
    return ether_header + arp_body

class NetworkInterface:
    def send(self, frame: bytes) -> None:
        raise NotImplementedError

    def receive(self, timeout: float = 0.1) -> Optional[bytes]:
        raise NotImplementedError

    def close(self) -> None:
        pass

class SimulatedBroadcastBus(NetworkInterface):
    def __init__(self, channel_id: str, node_id: str, drop_rate: float = 0.0):
        self.channel_id = channel_id
        self.node_id = node_id
        self.drop_rate = drop_rate
        
        import hashlib
        channel_hash = int(hashlib.md5(channel_id.encode("utf-8")).hexdigest()[:4], 16)
        self.port = 20000 + (channel_hash % 10000)
        self.mcast_grp = "239.255.42.99"
        
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_sock.bind(("", self.port))
        
        mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
        self.recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.recv_sock.setblocking(False)
        
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    def send(self, frame: bytes) -> None:
        if self.drop_rate > 0.0:
            import random
            if random.random() < self.drop_rate:
                return
        sender_tag = self.node_id.encode("utf-8")
        packet_payload = len(sender_tag).to_bytes(1, "big") + sender_tag + frame
        try:
            self.send_sock.sendto(packet_payload, (self.mcast_grp, self.port))
        except Exception:
            pass

    def receive(self, timeout: float = 0.1) -> Optional[bytes]:
        start = time.time()
        while time.time() - start < timeout:
            r, _, _ = select.select([self.recv_sock], [], [], min(0.02, timeout))
            if r:
                try:
                    data, _ = self.recv_sock.recvfrom(65535)
                    if len(data) > 1:
                        tag_len = data[0]
                        sender_tag = data[1:1 + tag_len].decode("utf-8", errors="ignore")
                        if sender_tag != self.node_id:
                            return data[1 + tag_len:]
                except Exception:
                    pass
        return None

    def close(self) -> None:
        try:
            self.recv_sock.close()
            self.send_sock.close()
        except Exception:
            pass

class RawSocketInterface(NetworkInterface):
    def __init__(self, interface_name: str = "eth0"):
        self.interface_name = interface_name
        self.sock = None
        self._init_socket()

    def _init_socket(self) -> None:
        if hasattr(socket, "AF_PACKET"):
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            self.sock.bind((self.interface_name, 0))
            self.sock.setblocking(False)

    def send(self, frame: bytes) -> None:
        if self.sock:
            self.sock.send(frame)

    def receive(self, timeout: float = 0.1) -> Optional[bytes]:
        if not self.sock:
            return None
        r, _, _ = select.select([self.sock], [], [], timeout)
        if r:
            try:
                data = self.sock.recv(65535)
                return data
            except (socket.error, BlockingIOError):
                return None
        return None

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

class TrailerCodec:
    @staticmethod
    def encapsulate(transport_packet: Packet, target_ip: str = "10.0.0.122") -> bytes:
        arp_base = build_ether_arp_frame(target_ip=target_ip)
        payload_bytes = transport_packet.pack()
        return arp_base + payload_bytes

    @staticmethod
    def extract(raw_frame: bytes) -> Optional[Packet]:
        if len(raw_frame) <= STANDARD_ARP_SIZE:
            return None
        trailer = raw_frame[STANDARD_ARP_SIZE:]
        return Packet.unpack(trailer)
