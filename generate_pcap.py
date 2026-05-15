#!/usr/bin/env python3
import socket
import struct
import sys

PCAP_MAGIC   = 0xa1b2c3d4 
PCAP_NETWORK = 1

ETHERTYPE_IP = 0x0800
PROTO_TCP    = 6
PROTO_UDP    = 17

_FAKE_MAC_A = b'\xde\xad\xbe\xef\x00\x01'
_FAKE_MAC_B = b'\xde\xad\xbe\xef\x00\x02'

def _eth(src=_FAKE_MAC_A, dst=_FAKE_MAC_B):
    return dst + src + struct.pack('!H', ETHERTYPE_IP)

def _ipv4(src, dst, proto, payload_len):
    return struct.pack('!BBHHHBBH4s4s',
        0x45,                    
        0,                      
        20 + payload_len,      
        0,                    
        0x4000,              
        64,                 
        proto,
        0,                 
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )

def _tcp(sport, dport):
    return struct.pack('!HHIIBBHHH',
        sport, dport,
        0, 0,     
        0x50,    
        0x02,   
        8192,  
        0, 0, 
    )

def _udp(sport, dport, payload_len):
    return struct.pack('!HHHH', sport, dport, 8 + payload_len, 0)

def _frame(src, dst, proto, dport, payload=b''):
    sport = 32768 + (dport % 32767)
    if proto == PROTO_TCP:
        transport = _tcp(sport, dport)
    else:
        transport = _udp(sport, dport, len(payload))
    ip  = _ipv4(src, dst, proto, len(transport) + len(payload))
    eth = _eth()
    return eth + ip + transport + payload

def _global_header():
    return struct.pack('<IHHiIII',
        PCAP_MAGIC, 2, 4, 
        0,               
        0,              
        65535,         
        PCAP_NETWORK,
    )

def _record(ts_sec, ts_usec, data, orig_len=None):
    if orig_len is None:
        orig_len = len(data)
    return struct.pack('<IIII', ts_sec, ts_usec, len(data), orig_len) + data

def write_pcap(path, records):
    with open(path, 'wb') as f:
        f.write(_global_header())
        for r in records:
            ts_sec, ts_usec, src, dst, proto, dport, payload = r[:7]
            orig_len = r[7] if len(r) > 7 else None
            data = _frame(src, dst, proto, dport, payload)
            f.write(_record(ts_sec, ts_usec, data, orig_len))
    print(f"[+] {len(records)} packet(s) written to '{path}'")


T_BIZ  = 1715248800   # 2024-05-09 10:00:00 UTC  (business hours)
T_NITE = 1715223600   # 2024-05-09 03:00:00 UTC  (off-hours)
TCP = PROTO_TCP
UDP = PROTO_UDP
RECORDS = []
RECORDS += [
    (T_BIZ,     0, '192.168.1.1', '8.8.8.8',       UDP, 53,  b'\x00'*20),
    (T_BIZ+1,   0, '192.168.1.2', '8.8.4.4',       UDP, 53,  b'\x00'*20),
    (T_BIZ+2,   0, '192.168.1.3', '93.184.216.34', TCP, 80,  b'GET / HTTP/1.1\r\n\r\n'),
    (T_BIZ+3,   0, '192.168.1.4', '1.1.1.1',       UDP, 53,  b'\x00'*20),
]
SCAN_PORTS = [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443, 9200, 6379]
for i, port in enumerate(SCAN_PORTS):
    RECORDS.append((T_BIZ + 100 + i*3, 0,
                    '192.168.1.100', '10.0.0.5', TCP, port, b''))
for i, host in enumerate(['192.168.1.10', '192.168.1.20', '192.168.1.30',
                           '192.168.1.40', '192.168.1.50', '192.168.1.60']):
    RECORDS.append((T_BIZ + 200 + i*20, 0,
                    '192.168.1.200', host, TCP, 445, b'\x00'*64))
EXFIL_ORIG_LEN = 15_728_640
RECORDS.append((T_NITE, 0,
                '192.168.1.50', '203.0.113.100', TCP, 443, b'', EXFIL_ORIG_LEN))
RECORDS.append((T_BIZ + 300, 0, '185.220.101.1', '192.168.1.1',  TCP, 22,   b''))
RECORDS.append((T_BIZ + 400, 0, '192.168.1.30',  '185.220.101.2', TCP, 9001, b''))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'sample.pcap'
    write_pcap(out, RECORDS)
    print()
    print("Load in Prolog:")
    print(f"  ?- load_pcap('{out}').")
    print()
    print("Or inspect with tshark:")
    print(f"  tshark -r {out} -T fields -e frame.time_epoch -e ip.src -e ip.dst")
    print(f"         -e tcp.dstport -e udp.dstport -e frame.len -E separator=,")
