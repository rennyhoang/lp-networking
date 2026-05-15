#!/usr/bin/env python3
"""
generate_pcap.py — Synthetic PCAP for testing network_monitor.pl

Produces sample.pcap (or a path given on the command line) containing
packets that trigger all five detection rules:

  PORT SCAN       192.168.1.100 → 10.0.0.5       (12 ports in 30 s)
  BRUTE FORCE     (auth log only — SSH is encrypted in PCAP)
  EXFIL           192.168.1.50  → 203.0.113.100   (15 MB, 03:00 UTC)
  LATERAL MOVE    192.168.1.200 → 192.168.1.10–60 (6 hosts via SMB)
  BLACKLIST       185.220.101.1 → 192.168.1.1     (inbound port 22)
                  192.168.1.30  → 185.220.101.2   (outbound port 9001)

No external dependencies — stdlib only.
"""

import socket
import struct
import sys

# ── PCAP global header constants ──────────────────────────────────────────────
PCAP_MAGIC   = 0xa1b2c3d4  # little-endian, microsecond timestamps
PCAP_NETWORK = 1           # Ethernet

ETHERTYPE_IP = 0x0800
PROTO_TCP    = 6
PROTO_UDP    = 17

_FAKE_MAC_A = b'\xde\xad\xbe\xef\x00\x01'
_FAKE_MAC_B = b'\xde\xad\xbe\xef\x00\x02'


# ── Low-level packet builders ─────────────────────────────────────────────────

def _eth(src=_FAKE_MAC_A, dst=_FAKE_MAC_B):
    return dst + src + struct.pack('!H', ETHERTYPE_IP)

def _ipv4(src, dst, proto, payload_len):
    return struct.pack('!BBHHHBBH4s4s',
        0x45,                    # version=4, IHL=5 (20 bytes, no options)
        0,                       # DSCP/ECN
        20 + payload_len,        # total length
        0,                       # identification
        0x4000,                  # DF flag, fragment offset 0
        64,                      # TTL
        proto,
        0,                       # checksum — tshark accepts 0 here
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )

def _tcp(sport, dport):
    return struct.pack('!HHIIBBHHH',
        sport, dport,
        0, 0,       # seq, ack
        0x50,       # data offset = 5 (20 bytes)
        0x02,       # SYN
        8192,       # window
        0, 0,       # checksum, urgent
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


# ── PCAP writer ───────────────────────────────────────────────────────────────

def _global_header():
    return struct.pack('<IHHiIII',
        PCAP_MAGIC, 2, 4,   # magic, major, minor version
        0,                  # GMT offset
        0,                  # timestamp accuracy
        65535,              # snap length
        PCAP_NETWORK,
    )

def _record(ts_sec, ts_usec, data, orig_len=None):
    """
    Write one packet record.  orig_len lets you report a wire size larger than
    the actual stored bytes — tshark exposes this as frame.len, so we use it to
    simulate a 15 MB exfil packet without bloating the file.
    """
    if orig_len is None:
        orig_len = len(data)
    return struct.pack('<IIII', ts_sec, ts_usec, len(data), orig_len) + data


def write_pcap(path, records):
    """
    records: list of (ts_sec, ts_usec, src, dst, proto, dport, payload, orig_len)
             orig_len is optional (pass None to derive from payload).
    """
    with open(path, 'wb') as f:
        f.write(_global_header())
        for r in records:
            ts_sec, ts_usec, src, dst, proto, dport, payload = r[:7]
            orig_len = r[7] if len(r) > 7 else None
            data = _frame(src, dst, proto, dport, payload)
            f.write(_record(ts_sec, ts_usec, data, orig_len))
    print(f"[+] {len(records)} packet(s) written to '{path}'")


# ── Scenario data ─────────────────────────────────────────────────────────────

# Base timestamps
T_BIZ  = 1715248800   # 2024-05-09 10:00:00 UTC  (business hours)
T_NITE = 1715223600   # 2024-05-09 03:00:00 UTC  (off-hours)

TCP = PROTO_TCP
UDP = PROTO_UDP

RECORDS = []

# ── Normal DNS / web traffic ──────────────────────────────────────────────────
RECORDS += [
    (T_BIZ,     0, '192.168.1.1', '8.8.8.8',       UDP, 53,  b'\x00'*20),
    (T_BIZ+1,   0, '192.168.1.2', '8.8.4.4',       UDP, 53,  b'\x00'*20),
    (T_BIZ+2,   0, '192.168.1.3', '93.184.216.34', TCP, 80,  b'GET / HTTP/1.1\r\n\r\n'),
    (T_BIZ+3,   0, '192.168.1.4', '1.1.1.1',       UDP, 53,  b'\x00'*20),
]

# ── PORT SCAN — 192.168.1.100 hits 12 ports on 10.0.0.5 in 30 s ──────────────
SCAN_PORTS = [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443, 9200, 6379]
for i, port in enumerate(SCAN_PORTS):
    RECORDS.append((T_BIZ + 100 + i*3, 0,
                    '192.168.1.100', '10.0.0.5', TCP, port, b''))

# ── LATERAL MOVEMENT — 192.168.1.200 reaches 6 internal SMB hosts ─────────────
for i, host in enumerate(['192.168.1.10', '192.168.1.20', '192.168.1.30',
                           '192.168.1.40', '192.168.1.50', '192.168.1.60']):
    RECORDS.append((T_BIZ + 200 + i*20, 0,
                    '192.168.1.200', host, TCP, 445, b'\x00'*64))

# ── DATA EXFILTRATION — 15 MB outbound at 03:00 UTC ──────────────────────────
# The actual stored frame is small (just headers); orig_len reports the wire
# size as 15 728 640 bytes, which tshark surfaces as frame.len.
# load_pcap uses frame.len as the Bytes field in connection/6.
EXFIL_ORIG_LEN = 15_728_640          # 15 MB — exceeds threshold(exfil_bytes, 10000000)
RECORDS.append((T_NITE, 0,
                '192.168.1.50', '203.0.113.100', TCP, 443, b'', EXFIL_ORIG_LEN))

# ── BLACKLIST — inbound from Tor exit node ────────────────────────────────────
RECORDS.append((T_BIZ + 300, 0, '185.220.101.1', '192.168.1.1',  TCP, 22,   b''))

# ── BLACKLIST — outbound to second blacklisted IP ─────────────────────────────
RECORDS.append((T_BIZ + 400, 0, '192.168.1.30',  '185.220.101.2', TCP, 9001, b''))


# ── Entry point ───────────────────────────────────────────────────────────────

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
