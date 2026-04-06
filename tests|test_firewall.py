import unittest
from src.firewall import inspect_packet

class TestFirewall(unittest.TestCase):
    def test_allowed_packet(self):
        packet = {'src_ip': '192.168.1.10', 'port': 80, 'protocol': 'TCP'}
        self.assertEqual(inspect_packet(packet), "Allowed")

    def test_blocked_ip(self):
        packet = {'src_ip': '192.168.1.100', 'port': 80, 'protocol': 'TCP'}
        self.assertEqual(inspect_packet(packet), "Blocked")

    def test_blocked_port(self):
        packet = {'src_ip': '192.168.1.10', 'port': 23, 'protocol': 'TCP'}
        self.assertEqual(inspect_packet(packet), "Blocked")

    def test_blocked_protocol(self):
        packet = {'src_ip': '192.168.1.10', 'port': 80, 'protocol': 'ICMP'}
        self.assertEqual(inspect_packet(packet), "Blocked")

if __name__ == "__main__":
    unittest.main()
