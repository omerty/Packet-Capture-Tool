import socket
import struct

def get_mac_addr(mac_bytes):
    return ':'.join(format(byte, '02x') for byte in mac_bytes)

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('!6s6sH', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:] 
    return dest_mac, src_mac, proto, data

def get_ip(addr):
    return '.'.join(map(str, addr))

def ipv4_headers(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind(('0.0.0.0', 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    print("Starting packet capture...")
    
    while True:
        try:
            raw_data, addr = s.recvfrom(65535)
            print(f"Received data from {addr}")
            eth = ethernet_head(raw_data)
            print('\nEthernet Frame')
            print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
            
            if eth[2] == 8:  # IP protocol
                ipv4 = ipv4_headers(eth[3])
                print('\tIPv4 Packet:')
                print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
                print('\t\tProtocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
                
                if ipv4[3] == 6:  # TCP
                    tcp = tcp_head(ipv4[6])
                    print('\t\tTCP Segment:')
                    print('\t\t\tSource Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                    print('\t\t\tSequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                    print('\t\t\tFlags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(tcp[4], tcp[5], tcp[6], tcp[7], tcp[8], tcp[9]))
                    if len(tcp[10]) > 0:
                        print('\t\t\tData: {}'.format(tcp[10]))
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
