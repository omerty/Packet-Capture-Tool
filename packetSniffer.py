import socket
import os

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)


#Binding the socket to the public interface
s.bind(("192.168.56.1", 0))

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
    print(s.recvfrom(65565))










