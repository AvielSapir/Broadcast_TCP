import time
import random
import threading
from enum import Enum, auto
from typing import Optional, Dict
from protocol import Packet, Flags
from framing import NetworkInterface, TrailerCodec
from reliability import RTOCalculator, ReassemblyBuffer, Fragmenter

class TCPState(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RCVD = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()

class UnacknowledgedPacket:
    def __init__(self, packet: Packet, send_time: float):
        self.packet = packet
        self.send_time = send_time
        self.retransmissions = 0

class ReliableTransportSession:
    def __init__(self, interface: NetworkInterface, session_id: Optional[int] = None, mtu: int = 1400):
        self.interface = interface
        self.session_id = session_id if session_id is not None else random.randint(1000, 65535)
        self.state = TCPState.CLOSED
        self.seq_num = random.randint(100, 10000)
        self.ack_num = 0
        self.peer_window = 65535
        self.rto_calc = RTOCalculator()
        self.fragmenter = Fragmenter(mtu)
        self.reassembly_buffer = None
        
        self.unacked_packets: Dict[int, UnacknowledgedPacket] = {}
        self.rx_stream = bytearray()
        
        self.lock = threading.RLock()
        self.running = False
        self.worker_thread = None
        self.on_packet_event = None
        self.stats = {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}

    def start(self) -> None:
        self.running = True
        self.worker_thread = threading.Thread(target=self._event_loop, daemon=True)
        self.worker_thread.start()

    def listen(self) -> None:
        with self.lock:
            self.state = TCPState.LISTEN
        self.start()

    def connect(self, timeout: float = 5.0) -> bool:
        with self.lock:
            self.state = TCPState.SYN_SENT
            syn_pkt = Packet(
                session_id=self.session_id,
                seq_num=self.seq_num,
                ack_num=0,
                flags=Flags.SYN,
                window=65535
            )
            self._send_packet(syn_pkt, track=True)
            self.seq_num += 1
        
        self.start()
        start = time.time()
        while time.time() - start < timeout:
            with self.lock:
                if self.state == TCPState.ESTABLISHED:
                    return True
            time.sleep(0.05)
        return False

    def send(self, data: bytes) -> bool:
        with self.lock:
            if self.state != TCPState.ESTABLISHED:
                return False
            chunks = self.fragmenter.fragment(data)
            for chunk in chunks:
                data_pkt = Packet(
                    session_id=self.session_id,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=Flags.DATA | Flags.ACK,
                    window=65535,
                    payload=chunk
                )
                self._send_packet(data_pkt, track=True)
                self.seq_num += len(chunk)
        return True

    def recv(self, max_bytes: int = 65535, timeout: float = 0.5) -> bytes:
        start = time.time()
        while time.time() - start < timeout:
            with self.lock:
                if len(self.rx_stream) > 0:
                    delivered = bytes(self.rx_stream[:max_bytes])
                    del self.rx_stream[:max_bytes]
                    return delivered
            time.sleep(0.01)
        return b""

    def close(self, timeout: float = 3.0) -> None:
        with self.lock:
            if self.state == TCPState.ESTABLISHED:
                self.state = TCPState.FIN_WAIT_1
                fin_pkt = Packet(
                    session_id=self.session_id,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=Flags.FIN | Flags.ACK,
                    window=65535
                )
                self._send_packet(fin_pkt, track=True)
                self.seq_num += 1
        
        start = time.time()
        while time.time() - start < timeout:
            with self.lock:
                if self.state in (TCPState.CLOSED, TCPState.TIME_WAIT):
                    break
            time.sleep(0.05)
            
        self.running = False
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=0.2)
        with self.lock:
            self.state = TCPState.CLOSED

    def _send_packet(self, packet: Packet, track: bool = False) -> None:
        frame = TrailerCodec.encapsulate(packet)
        self.interface.send(frame)
        self.stats["tx_packets"] += 1
        self.stats["tx_bytes"] += len(packet.payload)
        if track:
            self.unacked_packets[packet.seq_num] = UnacknowledgedPacket(packet, time.time())

    def _send_ack(self) -> None:
        ack_pkt = Packet(
            session_id=self.session_id,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            flags=Flags.ACK,
            window=65535
        )
        self._send_packet(ack_pkt, track=False)

    def _event_loop(self) -> None:
        while self.running:
            raw_frame = self.interface.receive(timeout=0.02)
            if raw_frame:
                packet = TrailerCodec.extract(raw_frame)
                if packet:
                    with self.lock:
                        self._handle_packet(packet)
            
            with self.lock:
                self._check_retransmissions()
            time.sleep(0.005)

    def _handle_packet(self, pkt: Packet) -> None:
        if self.state == TCPState.LISTEN:
            if pkt.is_syn():
                self.session_id = pkt.session_id
                self.ack_num = pkt.seq_num + 1
                self.reassembly_buffer = ReassemblyBuffer(self.ack_num)
                self.state = TCPState.SYN_RCVD
                syn_ack = Packet(
                    session_id=self.session_id,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=Flags.SYN | Flags.ACK,
                    window=65535
                )
                self._send_packet(syn_ack, track=True)
                self.seq_num += 1
                if self.on_packet_event:
                    self.on_packet_event("HANDSHAKE_SYN", pkt)
            return

        if pkt.session_id != self.session_id:
            return

        self.stats["rx_packets"] += 1
        self.stats["rx_bytes"] += len(pkt.payload)

        if pkt.is_ack():
            self.peer_window = pkt.window
            acked_seqs = [s for s, u in self.unacked_packets.items() if s < pkt.ack_num]
            now = time.time()
            for s in acked_seqs:
                u = self.unacked_packets.pop(s)
                if u.retransmissions == 0:
                    rtt = max(0.001, now - u.send_time)
                    self.rto_calc.update(rtt)

        if self.state == TCPState.SYN_SENT:
            if pkt.is_syn() and pkt.is_ack():
                self.ack_num = pkt.seq_num + 1
                self.reassembly_buffer = ReassemblyBuffer(self.ack_num)
                self.state = TCPState.ESTABLISHED
                self._send_ack()
                if self.on_packet_event:
                    self.on_packet_event("HANDSHAKE_SYNACK", pkt)
            return

        if self.state == TCPState.SYN_RCVD:
            if pkt.is_ack() and not pkt.is_syn():
                self.state = TCPState.ESTABLISHED
                if self.on_packet_event:
                    self.on_packet_event("HANDSHAKE_ESTABLISHED", pkt)

        if self.state == TCPState.ESTABLISHED:
            if pkt.is_data():
                if self.reassembly_buffer:
                    delivered = self.reassembly_buffer.insert(pkt.seq_num, pkt.payload)
                    pending_chunks = len(self.reassembly_buffer.out_of_order)
                    if self.on_packet_event:
                        self.on_packet_event("DATA_PACKET", pkt, pending_chunks=pending_chunks)
                    if delivered:
                        self.rx_stream.extend(delivered)
                        self.ack_num = self.reassembly_buffer.expected_seq
                        self._send_ack()
                    else:
                        self._send_ack()
            
            if pkt.is_fin():
                self.ack_num = pkt.seq_num + 1
                self.state = TCPState.CLOSE_WAIT
                self._send_ack()
                fin_pkt = Packet(
                    session_id=self.session_id,
                    seq_num=self.seq_num,
                    ack_num=self.ack_num,
                    flags=Flags.FIN | Flags.ACK,
                    window=65535
                )
                self._send_packet(fin_pkt, track=True)
                self.seq_num += 1
                self.state = TCPState.LAST_ACK
            return

        if self.state == TCPState.FIN_WAIT_1:
            if pkt.is_fin() and pkt.is_ack():
                self.ack_num = pkt.seq_num + 1
                self.state = TCPState.TIME_WAIT
                self._send_ack()
            elif pkt.is_ack():
                self.state = TCPState.FIN_WAIT_2
            return

        if self.state == TCPState.FIN_WAIT_2:
            if pkt.is_fin():
                self.ack_num = pkt.seq_num + 1
                self.state = TCPState.TIME_WAIT
                self._send_ack()
            return

        if self.state == TCPState.LAST_ACK:
            if pkt.is_ack():
                self.state = TCPState.CLOSED
                self.running = False
            return

    def _check_retransmissions(self) -> None:
        now = time.time()
        for seq, u in list(self.unacked_packets.items()):
            if now - u.send_time > self.rto_calc.rto:
                if u.retransmissions >= 5:
                    self.unacked_packets.pop(seq)
                    continue
                u.retransmissions += 1
                u.send_time = now
                self.rto_calc.backoff()
                frame = TrailerCodec.encapsulate(u.packet)
                self.interface.send(frame)
