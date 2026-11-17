import time
from typing import Dict, Optional, Tuple
from protocol import Packet, Flags

class RTOCalculator:
    def __init__(self, initial_rto: float = 1.0, min_rto: float = 0.2, max_rto: float = 5.0):
        self.srtt = None
        self.rttvar = None
        self.rto = initial_rto
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.alpha = 0.125
        self.beta = 0.25

    def update(self, rtt: float) -> None:
        if self.srtt is None:
            self.srtt = rtt
            self.rttvar = rtt / 2.0
        else:
            self.rttvar = (1 - self.beta) * self.rttvar + self.beta * abs(self.srtt - rtt)
            self.srtt = (1 - self.alpha) * self.srtt + self.alpha * rtt
        self.rto = max(self.min_rto, min(self.srtt + 4 * self.rttvar, self.max_rto))

    def backoff(self) -> None:
        self.rto = min(self.rto * 2.0, self.max_rto)

class ReassemblyBuffer:
    def __init__(self, initial_seq: int):
        self.expected_seq = initial_seq
        self.out_of_order: Dict[int, bytes] = {}

    def insert(self, seq_num: int, data: bytes) -> bytes:
        if seq_num < self.expected_seq:
            return b""
        if seq_num > self.expected_seq:
            self.out_of_order[seq_num] = data
            return b""
        
        delivered = bytearray(data)
        self.expected_seq += len(data)
        
        while self.expected_seq in self.out_of_order:
            next_chunk = self.out_of_order.pop(self.expected_seq)
            delivered.extend(next_chunk)
            self.expected_seq += len(next_chunk)
            
        return bytes(delivered)

class Fragmenter:
    def __init__(self, mtu: int = 1400):
        self.mtu = mtu

    def fragment(self, data: bytes) -> list:
        chunks = []
        for i in range(0, len(data), self.mtu):
            chunks.append(data[i:i + self.mtu])
        return chunks
