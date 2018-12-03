import csv
import ipaddress

class Firewall:

    rulesHashSet = set()

    # Constructor
    def __init__(self, path):
        with open(path, newline='') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if row[0] == 'Direction':
                    continue
                self.hash_rule(row)

    # Function returns the port range after getting parsed
    def getPortRange(self, ports):
        port_range = ports.split('-')
        if len(port_range) == 1:
            if int(port_range[0]) < 1 or int(port_range[0]) > 65535:
                return
            min_port_num = int(port_range[0])
            max_port_num = int(port_range[0])
        else:
            if int(port_range[0]) < 1 or int(port_range[0]) > 65535 or int(port_range[1]) < 1 or int(port_range[1]) > 65535:
                return
            min_port_num = int(port_range[0])
            max_port_num = int(port_range[1])
        return (min_port_num, max_port_num)

    # Function returns the IP range after getting parsed
    def getIpRange(self, ips):
        ip_range = ips.split('-')
        if len(ip_range) == 1:
            ip_vals_min = ipaddress.IPv4Address(ip_range[0])
            ip_vals_max = ipaddress.IPv4Address(ip_range[0])
        else:
            ip_vals_min = ipaddress.IPv4Address(ip_range[0])
            ip_vals_max = ipaddress.IPv4Address(ip_range[1])
        return (ip_vals_min, ip_vals_max)

    # This function hashes all the values as a tuple and stores them in a hashset so that we have have O(1) time during retrival
    def hash_rule(self, line):
        port_range = self.getPortRange(line[2])
        start_ip, end_ip = self.getIpRange(line[3])
        for i in range(port_range[0], port_range[1]+1):
            for ip_int in range(int(start_ip), int(end_ip)+1):
                _hash = (line[0], line[1], str(i), ipaddress.IPv4Address(ip_int))
                Firewall.rulesHashSet.add(hash(_hash))

    def accept_packet(self,direction,protocol,port,ip):
        _hash = hash((direction,protocol,str(port),ipaddress.IPv4Address(ip)))
        if _hash in Firewall.rulesHashSet:
            return True
        else:
            return False                
    
fw = Firewall('C:/Users/reddy/Downloads/firewall_rules_common.csv')
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
print(fw.accept_packet("inbound", "udp", 1, "255.255.255.255"))
print(fw.accept_packet("outbound", "tcp", 65535, "255.255.255.255"))
print(fw.accept_packet("inbound", "udp", 65535, "255.255.255.254"))
print(fw.accept_packet("outbound", "tcp", 1, "0.0.0.1"))
print(fw.accept_packet("inbound", "tcp", 45, "0.0.0.1"))
print(fw.accept_packet("inbound", "tcp", 450, "0.0.0.245"))
print(fw.accept_packet("inbound", "tcp", 500, "2.3.0.1"))
print(fw.accept_packet("inbound", "tcp", 460, "0.0.1.0"))
print(fw.accept_packet("inbound", "tcp", 460, "0.0.1.1"))
print(fw.accept_packet("inbound", "tcp", 1200, "0.0.1.23"))
print(fw.accept_packet("inbound", "tcp", 1300, "0.0.2.3"))