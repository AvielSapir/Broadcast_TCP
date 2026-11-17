import struct
import zlib
from enum import IntEnum

MAGIC = 0xBC70

class Flags(IntEnum):
    SYN = 0x01
    ACK = 0x02
    DATA = 0x04
    FIN = 0x08
    RST = 0x10

HEADER_STRUCT = struct.Struct("!HHIIBHHH")
HEADER_SIZE = HEADER_STRUCT.size

class Packet:
    def __init__(self, session_id: int, seq_num: int, ack_num: int, flags: int, window: int, payload: bytes = b""):
        self.magic = MAGIC
        self.session_id = session_id
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window = window
        self.payload = payload

    def pack(self) -> bytes:
        data_len = len(self.payload)
        checksum = 0
        header_without_checksum = HEADER_STRUCT.pack(
            self.magic,
            self.session_id,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.window,
            data_len,
            checksum
        )
        checksum = zlib.crc32(header_without_checksum + self.payload) & 0xFFFF
        full_header = HEADER_STRUCT.pack(
            self.magic,
            self.session_id,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.window,
            data_len,
            checksum
        )
        return full_header + self.payload

    @classmethod
    def unpack(cls, raw_bytes: bytes):
        if len(raw_bytes) < HEADER_SIZE:
            return None
        magic, session_id, seq_num, ack_num, flags, window, data_len, checksum = HEADER_STRUCT.unpack(raw_bytes[:HEADER_SIZE])
        if magic != MAGIC:
            return None
        if len(raw_bytes) < HEADER_SIZE + data_len:
            return None
        payload = raw_bytes[HEADER_SIZE:HEADER_SIZE + data_len]
        test_header = HEADER_STRUCT.pack(
            magic,
            session_id,
            seq_num,
            ack_num,
            flags,
            window,
            data_len,
            0
        )
        calc_checksum = zlib.crc32(test_header + payload) & 0xFFFF
        if calc_checksum != checksum:
            return None
        return cls(session_id, seq_num, ack_num, flags, window, payload)

    def is_syn(self) -> bool:
        return bool(self.flags & Flags.SYN)

    def is_ack(self) -> bool:
        return bool(self.flags & Flags.ACK)

    def is_data(self) -> bool:
        return bool(self.flags & Flags.DATA)

    def is_fin(self) -> bool:
        return bool(self.flags & Flags.FIN)

    def is_rst(self) -> bool:
        return bool(self.flags & Flags.RST)
