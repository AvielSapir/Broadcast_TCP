import time
import unittest
from protocol import Packet, Flags, MAGIC
from framing import SimulatedBroadcastBus, TrailerCodec, build_ether_arp_frame, STANDARD_ARP_SIZE
from reliability import RTOCalculator, ReassemblyBuffer, Fragmenter
from session import ReliableTransportSession, TCPState
from crypto import CryptoEngine

class TestPacketProtocol(unittest.TestCase):
    def test_serialization(self):
        pkt = Packet(session_id=101, seq_num=1000, ack_num=500, flags=Flags.SYN | Flags.ACK, window=4096, payload=b"HELLO")
        raw = pkt.pack()
        unpacked = Packet.unpack(raw)
        self.assertIsNotNone(unpacked)
        self.assertEqual(unpacked.session_id, 101)
        self.assertEqual(unpacked.seq_num, 1000)
        self.assertEqual(unpacked.ack_num, 500)
        self.assertEqual(unpacked.flags, Flags.SYN | Flags.ACK)
        self.assertEqual(unpacked.window, 4096)
        self.assertEqual(unpacked.payload, b"HELLO")

    def test_corrupted_checksum(self):
        pkt = Packet(session_id=1, seq_num=1, ack_num=0, flags=Flags.DATA, window=100, payload=b"DATA")
        raw = bytearray(pkt.pack())
        raw[-1] ^= 0xFF
        self.assertIsNone(Packet.unpack(bytes(raw)))

class TestTrailerCodec(unittest.TestCase):
    def test_encap_decap(self):
        pkt = Packet(session_id=202, seq_num=2, ack_num=1, flags=Flags.DATA, window=1024, payload=b"TEST")
        frame = TrailerCodec.encapsulate(pkt)
        self.assertGreater(len(frame), STANDARD_ARP_SIZE)
        extracted = TrailerCodec.extract(frame)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted.session_id, 202)
        self.assertEqual(extracted.payload, b"TEST")

class TestReassembly(unittest.TestCase):
    def test_out_of_order(self):
        buf = ReassemblyBuffer(initial_seq=0)
        d1 = buf.insert(6, b"WORLD")
        self.assertEqual(d1, b"")
        d2 = buf.insert(0, b"HELLO_")
        self.assertEqual(d2, b"HELLO_WORLD")
        self.assertEqual(buf.expected_seq, 11)

class TestCrypto(unittest.TestCase):
    def test_encrypt_decrypt(self):
        engine = CryptoEngine(b"test_secret_key_12345")
        data = b"Secret payload message"
        ct = engine.encrypt(data)
        self.assertNotEqual(ct, data)
        pt = engine.decrypt(ct)
        self.assertEqual(pt, data)

class TestTransportSession(unittest.TestCase):
    def test_handshake_and_transfer(self):
        bus_name = "test_bus_transfer"
        srv_bus = SimulatedBroadcastBus(bus_name, "srv")
        cli_bus = SimulatedBroadcastBus(bus_name, "cli")

        srv = ReliableTransportSession(srv_bus)
        srv.listen()

        cli = ReliableTransportSession(cli_bus)
        connected = cli.connect(timeout=2.0)
        self.assertTrue(connected)
        time.sleep(0.05)
        self.assertEqual(cli.state, TCPState.ESTABLISHED)
        self.assertEqual(srv.state, TCPState.ESTABLISHED)

        test_msg = b"Broadcast TCP covert channel active!"
        cli.send(test_msg)

        received = srv.recv(timeout=2.0)
        self.assertEqual(received, test_msg)

        cli.close()
        srv.close()
        srv_bus.close()
        cli_bus.close()

    def test_retransmission_under_loss(self):
        bus_name = "test_bus_loss"
        srv_bus = SimulatedBroadcastBus(bus_name, "srv")
        cli_bus = SimulatedBroadcastBus(bus_name, "cli", drop_rate=0.2)

        srv = ReliableTransportSession(srv_bus)
        srv.listen()

        cli = ReliableTransportSession(cli_bus)
        connected = cli.connect(timeout=3.0)
        self.assertTrue(connected)

        test_msg = b"Resilient delivery over lossy broadcast"
        cli.send(test_msg)

        received = srv.recv(timeout=3.0)
        self.assertEqual(received, test_msg)

        cli.close()
        srv.close()
        srv_bus.close()
        cli_bus.close()

if __name__ == "__main__":
    unittest.main()
