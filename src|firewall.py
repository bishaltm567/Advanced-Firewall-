import json
from logger import setup_logger
from alert import send_alert

# Load rules from JSON
with open('rules.json') as f:
    rules = json.load(f)

logger = setup_logger()

def check_ip(ip_address):
    if ip_address in rules['blocked_ips']:
        logger.warning(f"Blocked IP: {ip_address}")
        send_alert(f"Blocked IP detected: {ip_address}")
        return False
    return True

def check_port(port):
    if port in rules['blocked_ports']:
        logger.warning(f"Blocked Port: {port}")
        send_alert(f"Blocked Port detected: {port}")
        return False
    return True

def inspect_packet(packet):
    ip = packet.get('src_ip')
    port = packet.get('port')
    protocol = packet.get('protocol')

    if not check_ip(ip) or not check_port(port):
        return "Blocked"
    if protocol not in rules['allowed_protocols']:
        logger.warning(f"Blocked Protocol: {protocol}")
        return "Blocked"
    logger.info(f"Allowed Packet: {packet}")
    return "Allowed"

if __name__ == "__main__":
    # Test packet example
    test_packet = {'src_ip': '192.168.1.10', 'port': 22, 'protocol': 'TCP'}
    result = inspect_packet(test_packet)
    print(f"Packet Status: {result}")
