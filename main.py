import socket 
import time
import sys
import netifaces
from ctypes import *
from struct import *


#getting ip address =======================================================================================================
#https://pythonguides.com/python-get-an-ip-address/ 
try: 
    dstaddr = sys.argv[1]
    dstad = socket.gethostbyname(dstaddr)
    
except IndexError:
    print("Enter with ip \nex: sudo python3 main.py 8.8.8.8")
    sys.exit()
#check ip is valid or not====================
except socket.gaierror:
   print("Invalid hostname or IP")
   sys.exit()


#ICMP pack =================================================================================================================
# https://gist.github.com/shawwwn/91cc8979e33e82af6d99ec34c38195fb
def checksum(data):
    if len(data) & 0x1: # Odd number of bytes
        data += b'\0'
    cs = 0
    for pos in range(0, len(data), 2):
        b1 = data[pos]
        b2 = data[pos + 1]
        cs += (b1 << 8) + b2
    while cs >= 0x10000:
        cs = (cs & 0xffff) + (cs >> 16)
    cs = ~cs & 0xffff
    return cs


def icmp_pack(sequ):
    i_type = 8
    i_code = 0
    i_check = 0
    i_id = 5656
    i_seq = sequ #sequence number will increasing by one 

    icmp_header = pack('!bbHHh', i_type, i_code, i_check, i_id, i_seq)
    size = 64
    data = b'Q'*size

    get_checksum = checksum(icmp_header + data)
    get_checksum = pack('H', socket.htons(get_checksum))
    icmp_header = pack('!bb2sHh', i_type, i_code, get_checksum , i_id, i_seq)
    packet = icmp_header + data
    return packet



pack_count = 1 #packet count it will incresing by one each loop for update sequence number
rcv_count = 0
while True:
    try:
        #send packet ==========================================================================
        packet = icmp_pack(pack_count)
        s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stime = time.time()
        s.sendto(packet,(dstad, 1))

        class IP(Structure):
            _fields_ = [
                ("version", c_ubyte, 4),
                ("ihl", c_ubyte, 4 ),
                ("tos", c_ubyte),
                ("tl", c_ushort),
                ("id", c_ushort),
                ("offset", c_ushort),
                ("ttl", c_ubyte),
                ("p_num", c_ubyte),
                ("chsum", c_ushort),
                ("src", c_uint32),
                ("des", c_uint32)

            ]

            def __new__(self, socket_buffer=None):
                return self.from_buffer_copy(socket_buffer)

            def __init__(self, socket_buffer=None):
            
                self.src_addr = socket.inet_ntoa(pack("@I", self.src))
                self.dst_addr = socket.inet_ntoa(pack("@I", self.des))
            

        class ICMP(Structure):
            _fields_=[
                ("type", c_ubyte),
                ("code", c_ubyte),
                ("chsum", c_ushort),
                ("id", c_ushort),
                ("seq", c_uint16)
            ]
            def __new__(self, socket_buffer=None):
                return self.from_buffer_copy(socket_buffer)

            def __init__(self, socket_buffer=None):
                self.seq = socket.htons(self.seq)
                self.id = socket.htons(self.id)
                pass
    
    
        #recev packet================================================================================
        recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_sock.bind(('ens33', 0))
        recv_sock.settimeout(5)
        recv_data = recv_sock.recvfrom(65536)[0]
        icmp = ICMP(recv_data[34:])
     
        #filter icmp reply =======================================================
        if icmp.type == 0 and icmp.id == 5656 :
            rtime = time.time()
            delay = rtime - stime  
            delay = delay * 1000 
            delay = round(delay, 2)
            ip = IP(recv_data[14:])
            data_len = len(recv_data[42:])
            print(f"{data_len} bytes from {ip.src_addr}: ICMP_seq={icmp.seq} ttl={ip.ttl} {delay}ms" )
            rcv_count += 1
    
        time.sleep(2)
        pack_count += 1

    except socket.timeout:
        print("Request timeout .....")
        pass
    except KeyboardInterrupt:
        print ("\n",f"{pack_count} packets transmitted, {rcv_count} received,")
        print (" {:.0%} successful".format(rcv_count/pack_count))
        print (" exiting....")
        break
    