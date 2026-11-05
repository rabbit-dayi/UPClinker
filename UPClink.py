
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UPC captive portal watchdog. Python 3.9+, no Python dependencies.

Linux: uses AF_PACKET for ARP and UDP/DNS where CAP_NET_RAW is available;
       HTTP/TLS still uses the kernel TCP stack, bound to the chosen interface.
Windows: uses Npcap's native wpcap.dll (when installed and usable) for
         Ethernet/ARP/IP/UDP/DNS; otherwise direct UDP then system DNS fallback.
         HTTP/TLS still uses TCP sockets pinned to the chosen source IPv4.

This authenticates through the official portal; raw packets do not bypass
campus authentication. Never sends credentials to an unapproved portal host.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import errno
import getpass
import html
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

IS_LINUX = sys.platform.startswith("linux")
DNS_SERVERS = ("121.251.251.250", "121.251.251.251")
PORTAL_HOSTS = ("wlan.upc.edu.cn", "lan.upc.edu.cn")
LOGIN_PATH = "/eportal/InterFace.do?method=login"
SERVICES = {"1": "", "2": "telecom", "3": "unicom", "4": "cmcc"}
# Deliberately use well-defined connectivity checks instead of arbitrary 200s.
CHECKS = (
    ("http://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ("http://captive.apple.com/hotspot-detect.html", 200, b"Success"),
)
MAX_HTTP_BYTES = 32 * 1024
USER_AGENT = "UPCPortalWatchdog/2.1 (Python stdlib)"

# Keep the original [+/ -/ */ !] status style, including the Windows console.
LOG_COLORS = {"+": "\033[32m", "-": "\033[31m", "*": "\033[36m", "!": "\033[33m"}
COLOR_RESET = "\033[0m"

def supports_ansi_color() -> bool:
    """Use VT on Windows 10/11; do not emit escapes to files/services."""
    if not getattr(sys.stdout, "isatty", lambda: False)() or "NO_COLOR" in os.environ:
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    if os.name != "nt":
        return True
    try:
        kernel = ctypes.windll.kernel32
        kernel.GetStdHandle.argtypes = [ctypes.c_int32]
        kernel.GetStdHandle.restype = ctypes.c_void_p  # HANDLE is 64-bit on Win64.
        kernel.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel.GetConsoleMode.restype = ctypes.c_int
        kernel.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.SetConsoleMode.restype = ctypes.c_int
        handle = kernel.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(mode.value & 0x0004) or bool(
            kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ValueError):
        return False


def internet_checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    words = struct.unpack("!%dH" % (len(payload) // 2), payload)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def parse_a_record(dns: bytes, txid: int) -> tuple[str, int] | None:
    """Parse an IPv4 DNS reply, respecting compressed labels and record bounds."""
    if len(dns) < 12:
        return None
    ident, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", dns)
    if ident != txid or not (flags & 0x8000) or (flags & 0x000f) != 0 or qd != 1:
        return None

    def skip_name(offset: int) -> int:
        for _ in range(128):
            if offset >= len(dns):
                raise ValueError("truncated DNS name")
            length = dns[offset]
            if length & 0xc0 == 0xc0:
                if offset + 2 > len(dns):
                    raise ValueError("truncated DNS pointer")
                pointer = ((length & 0x3f) << 8) | dns[offset + 1]
                if pointer >= len(dns):
                    raise ValueError("invalid DNS pointer")
                return offset + 2
            if length & 0xc0:
                raise ValueError("invalid DNS label")
            offset += 1
            if length == 0:
                return offset
            if length > 63 or offset + length > len(dns):
                raise ValueError("invalid DNS label length")
            offset += length
        raise ValueError("DNS label limit reached")

    try:
        pos = 12
        pos = skip_name(pos)
        if pos + 4 > len(dns):
            return None
        qtype, qclass = struct.unpack_from("!HH", dns, pos)
        if qtype != 1 or qclass != 1:
            return None
        pos += 4
        for _ in range(min(an, 64)):
            pos = skip_name(pos)
            if pos + 10 > len(dns):
                return None
            rr_type, rr_class, ttl, length = struct.unpack_from("!HHIH", dns, pos)
            pos += 10
            if pos + length > len(dns):
                return None
            if rr_type == 1 and rr_class == 1 and length == 4:
                return socket.inet_ntoa(dns[pos:pos+4]), max(5, min(ttl, 300))
            pos += length
    except (ValueError, struct.error):
        return None
    return None


def build_dns_query(host: str, txid: int) -> bytes:
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", host):
        raise ValueError("invalid DNS hostname")
    labels = host.rstrip(".").encode("ascii").split(b".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS labels")
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def udp_dns_a(host: str, server: str, source_ip: str = "", timeout: float = 0.6):
    """Direct UDP to specified DNS server, avoiding system resolver policies/cache."""
    txid = random.randrange(1, 65536)
    query = build_dns_query(host, txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        if source_ip:
            sock.bind((source_ip, 0))
        sock.sendto(query, (server, 53))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                data, sender = sock.recvfrom(4096)
            except socket.timeout:
                break
            if sender[0] != server or sender[1] != 53:
                continue
            answer = parse_a_record(data, txid)
            if answer:
                return answer
    return None


@dataclass(frozen=True)
class Network:
    name: str
    ipv4: str
    netmask: str
    gateway: str
    mac: bytes
    capture_guid: str = ""
    status: str = "up"

    def next_hop(self, target: str) -> str:
        network = ipaddress.IPv4Network(f"{self.ipv4}/{self.netmask}", strict=False)
        return target if ipaddress.IPv4Address(target) in network else self.gateway


def linux_network(interface: str | None) -> Network | None:
    if not IS_LINUX:
        return None
    routes = []
    try:
        with open("/proc/net/route", encoding="ascii") as route_file:
            next(route_file, None)
            for line in route_file:
                fields = line.split()
                if len(fields) < 11 or fields[1] != "00000000":
                    continue
                if not int(fields[3], 16) & 1:
                    continue
                gw = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
                routes.append((int(fields[6]), fields[0], gw))
    except (OSError, ValueError):
        return None
    routes.sort()
    if interface:
        routes = [entry for entry in routes if entry[1] == interface]
    if not routes:
        return None
    _, iface, gateway = routes[0]
    try:
        import fcntl  # Linux only
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            request = struct.pack("256s", iface.encode("utf-8")[:15])
            ipv4 = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, request)[20:24])
            mask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x891b, request)[20:24])
        mac = bytes.fromhex(Path(f"/sys/class/net/{iface}/address").read_text().strip().replace(":", ""))
        if len(mac) != 6:
            return None
        return Network(iface, ipv4, mask, gateway, mac)
    except (OSError, ValueError):
        return None


WIN_ROUTE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$out = @()
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
foreach ($route in $routes) {
    try {
        $index = [uint32]$route.InterfaceIndex
        $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop
        $addresses = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.IPAddress -notlike '169.254.*' -and $_.AddressState -in @('Preferred', 'Deprecated')
        })
        if ($addresses.Count -eq 0) { continue }
        $ip = $addresses[0]
        $ifconfig = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop
        $out += [pscustomobject]@{
            Name = [string]$adapter.Name
            Index = $index
            Ip = [string]$ip.IPAddress
            Prefix = [int]$ip.PrefixLength
            Gateway = [string]$route.NextHop
            Mac = [string]$adapter.MacAddress
            Guid = [string]$adapter.InterfaceGuid
            Status = [string]$adapter.Status
            Metric = [int]$route.RouteMetric + [int]$ifconfig.InterfaceMetric
        }
    } catch { continue }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
'''


def select_windows_network(routes: list[dict], interface: str | None) -> Network | None:
    """Pure parser, kept separate from PowerShell so it is unit-testable."""
    valid = []
    for item in routes:
        try:
            if interface and str(item["Name"]).casefold() != interface.casefold() and str(item["Index"]) != interface:
                continue
            if str(item["Status"]).casefold() != "up":
                continue
            ip = str(ipaddress.IPv4Address(item["Ip"]))
            prefix = int(item["Prefix"])
            if prefix < 0 or prefix > 32:
                continue
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
            gateway = str(ipaddress.IPv4Address(item["Gateway"]))
            if gateway == "0.0.0.0":
                continue
            mac = bytes.fromhex(re.sub(r"[:-]", "", str(item["Mac"])))
            if len(mac) != 6:
                continue
            guid = str(item.get("Guid", "")).strip("{} ")
            if not re.fullmatch(r"[0-9A-Fa-f-]{36}", guid):
                guid = ""
            net = Network(str(item["Name"]), ip, mask, gateway, mac, guid,
                          str(item["Status"]))
            valid.append((int(item["Metric"]), net))
        except (KeyError, ValueError, TypeError):
            continue
    return min(valid, key=lambda row: row[0])[1] if valid else None


def windows_network(interface: str | None) -> Network | None:
    if os.name != "nt":
        return None
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WIN_ROUTE_SCRIPT],
            capture_output=True, encoding="utf-8", errors="replace", timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return None
        data = json.loads(completed.stdout.lstrip("\ufeff"))
        if isinstance(data, dict):
            data = [data]
        return select_windows_network(data, interface) if isinstance(data, list) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


class _PcapTimeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapHeader(ctypes.Structure):
    _fields_ = [("ts", _PcapTimeval), ("caplen", ctypes.c_uint), ("length", ctypes.c_uint)]


class _BPFProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


@lru_cache(maxsize=1)
def npcap_library():
    """Only load the system-installed DLL; do not import a DLL from cwd."""
    if os.name != "nt":
        raise OSError("Npcap is Windows-only")
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    paths = [root / "System32" / "Npcap" / "wpcap.dll",
             root / "System32" / "wpcap.dll"]
    for path in paths:
        if path.is_file():
            # Npcap's Packet.dll dependency may live beside wpcap.dll.
            with os.add_dll_directory(str(path.parent)):
                lib = ctypes.WinDLL(str(path))
            lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                          ctypes.c_int, ctypes.c_char_p]
            lib.pcap_open_live.restype = ctypes.c_void_p
            lib.pcap_close.argtypes = [ctypes.c_void_p]
            lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
            lib.pcap_sendpacket.restype = ctypes.c_int
            lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapHeader)),
                                        ctypes.POINTER(ctypes.c_void_p)]
            lib.pcap_next_ex.restype = ctypes.c_int
            lib.pcap_datalink.argtypes = [ctypes.c_void_p]
            lib.pcap_datalink.restype = ctypes.c_int
            lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BPFProgram),
                                         ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
            lib.pcap_compile.restype = ctypes.c_int
            lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BPFProgram)]
            lib.pcap_setfilter.restype = ctypes.c_int
            lib.pcap_freecode.argtypes = [ctypes.POINTER(_BPFProgram)]
            return lib
    raise OSError("未安装 Npcap 或找不到系统 wpcap.dll")


class NpcapSession:
    """Npcap-backed Ethernet frame I/O without Scapy or Python add-ons."""
    def __init__(self, network: Network, timeout: float):
        self.network = network
        self.timeout = timeout
        self.lib = npcap_library()
        self.handle = None

    def __enter__(self):
        if not self.network.capture_guid:
            raise OSError("网卡缺少有效 GUID，无法打开 Npcap 捕获设备")
        device = rf"\Device\NPF_{{{self.network.capture_guid}}}".encode("ascii")
        errbuf = ctypes.create_string_buffer(512)
        self.handle = self.lib.pcap_open_live(device, 65535, 0, 150, errbuf)
        if not self.handle:
            raise OSError("Npcap 无法打开网卡（可能需要管理员或允许普通用户抓包）: " +
                          errbuf.value.decode("utf-8", "replace"))
        if self.lib.pcap_datalink(self.handle) != 1:  # DLT_EN10MB
            self.__exit__(None, None, None)
            raise OSError("该 Npcap 网卡不是以太网帧封装")
        program = _BPFProgram()
        if self.lib.pcap_compile(self.handle, ctypes.byref(program),
                                 b"arp or (ip and udp and src port 53)", 1, 0xffffffff) == 0:
            try:
                self.lib.pcap_setfilter(self.handle, ctypes.byref(program))
            finally:
                self.lib.pcap_freecode(ctypes.byref(program))
        return self

    def __exit__(self, *_):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None

    def send(self, packet: bytes):
        buf = ctypes.create_string_buffer(packet)
        if self.lib.pcap_sendpacket(self.handle, buf, len(packet)) != 0:
            raise OSError("Npcap 以太网帧发送失败")

    def settimeout(self, seconds: float):
        self.timeout = seconds

    def recv(self, maxlen: int) -> bytes:
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            header_ptr = ctypes.POINTER(_PcapHeader)()
            data = ctypes.c_void_p()
            outcome = self.lib.pcap_next_ex(self.handle, ctypes.byref(header_ptr), ctypes.byref(data))
            if outcome == 1:
                if header_ptr and data.value:
                    return ctypes.string_at(data, min(maxlen, header_ptr.contents.caplen))
            elif outcome < 0:
                raise OSError("Npcap 读取捕获数据失败")
        raise socket.timeout("Npcap 接收超时")


class RawEthernet:
    """L2 ARP and handcrafted IPv4/UDP/DNS without the host's UDP/DNS stack."""
    def __init__(self, network: Network, timeout: float = 0.65):
        self.net = network
        self.timeout = timeout
        self.arp_cache: dict[str, tuple[bytes, float]] = {}
        self.arp_failed_until: dict[str, float] = {}
        self.raw_disabled_until = 0.0

    def _socket(self):
        if os.name == "nt":
            return NpcapSession(self.net, self.timeout)
        if IS_LINUX:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((self.net.name, 0))
            sock.settimeout(self.timeout)
            return sock
        raise OSError("此操作系统不支持原始以太网帧接口")

    def arp(self, target: str) -> bytes | None:
        if time.monotonic() < self.raw_disabled_until:
            return None
        if time.monotonic() < self.arp_failed_until.get(target, 0):
            return None
        item = self.arp_cache.get(target)
        if item and item[1] > time.monotonic():
            return item[0]
        frame = (b"\xff" * 6 + self.net.mac + b"\x08\x06" +
                 struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) +
                 self.net.mac + socket.inet_aton(self.net.ipv4) +
                 b"\x00" * 6 + socket.inet_aton(target))
        try:
            with self._socket() as sock:
                for _ in range(2):
                    sock.send(frame)
                    deadline = time.monotonic() + self.timeout
                    while time.monotonic() < deadline:
                        sock.settimeout(max(0.01, deadline - time.monotonic()))
                        try:
                            data = sock.recv(2048)
                        except socket.timeout:
                            break
                        if len(data) < 42 or data[12:14] != b"\x08\x06":
                            continue
                        if data[20:22] != b"\x00\x02":
                            continue
                        if data[28:32] != socket.inet_aton(target):
                            continue
                        if data[38:42] != socket.inet_aton(self.net.ipv4):
                            continue
                        mac = data[22:28]
                        self.arp_cache[target] = (mac, time.monotonic() + 120)
                        self.arp_failed_until.pop(target, None)
                        return mac
        except OSError:
            self.raw_disabled_until = time.monotonic() + 30
            return None
        self.arp_failed_until[target] = time.monotonic() + 3
        return None

    def dns_a(self, host: str, dns_server: str) -> tuple[str, int] | None:
        if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9.-]+", host):
            return None
        next_hop = self.net.next_hop(dns_server)
        if next_hop == "0.0.0.0":
            return None
        gateway_mac = self.arp(next_hop)
        if gateway_mac is None:
            return None
        try:
            txid = random.randint(1, 65535)
            srcport = random.randint(20000, 62000)
            query = build_dns_query(host, txid)
            src_ip = socket.inet_aton(self.net.ipv4)
            dst_ip = socket.inet_aton(dns_server)
            udp_len = 8 + len(query)
            pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)
            udp_head = struct.pack("!HHHH", srcport, 53, udp_len, 0)
            udp_sum = internet_checksum(pseudo + udp_head + query) or 0xffff
            udp = struct.pack("!HHHH", srcport, 53, udp_len, udp_sum) + query
            total_len = 20 + len(udp)
            ip_head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len,
                                  random.randint(0, 65535), 0x4000, 64, 17,
                                  0, src_ip, dst_ip)
            ip_sum = internet_checksum(ip_head)
            ip_head = ip_head[:10] + struct.pack("!H", ip_sum) + ip_head[12:]
            frame = gateway_mac + self.net.mac + b"\x08\x00" + ip_head + udp
            with self._socket() as sock:
                for _ in range(2):
                    sock.send(frame)
                    deadline = time.monotonic() + self.timeout
                    while time.monotonic() < deadline:
                        sock.settimeout(max(0.01, deadline - time.monotonic()))
                        try:
                            pkt = sock.recv(4096)
                        except socket.timeout:
                            break
                        if len(pkt) < 14 + 20 + 8 + 12 or pkt[12:14] != b"\x08\x00":
                            continue
                        ip = pkt[14:]
                        if (ip[0] >> 4) != 4 or ip[9] != 17:
                            continue
                        ihl = (ip[0] & 0x0f) * 4
                        if ihl < 20 or len(ip) < ihl + 8:
                            continue
                        total = struct.unpack_from("!H", ip, 2)[0]
                        if total < ihl + 8 or len(ip) < total:
                            continue
                        if ip[12:16] != dst_ip or ip[16:20] != src_ip:
                            continue
                        if struct.unpack_from("!H", ip, 6)[0] & 0x3fff:
                            continue  # Never interpret IP fragments as complete DNS answers.
                        udp_rx = ip[ihl:total]
                        if len(udp_rx) < 8:
                            continue
                        sport, dport, length, _ = struct.unpack_from("!HHHH", udp_rx)
                        if sport != 53 or dport != srcport or not (8 <= length <= len(udp_rx)):
                            continue
                        answer = parse_a_record(udp_rx[8:length], txid)
                        if answer:
                            return answer
        except (OSError, ValueError, struct.error):
            return None
        return None


class Resolver:
    def __init__(self, dns_servers: tuple[str, ...] = DNS_SERVERS):
        self.servers = dns_servers
        self.cache: dict[tuple[str, str], tuple[str, float]] = {}
        self.raw_unavailable_notice = False
        self.raw_clients: dict[Network, RawEthernet] = {}
        self.last_method = ""

    def clear(self):
        self.cache.clear()
        self.raw_clients.clear()

    def resolve(self, host: str, network: Network | None) -> str:
        try:
            return str(ipaddress.IPv4Address(host))
        except ipaddress.AddressValueError:
            pass
        key = (host.lower(), network.name + ":" + network.ipv4 if network else "system")
        cached = self.cache.get(key)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        if network and (IS_LINUX or os.name == "nt"):
            raw = self.raw_clients.setdefault(network, RawEthernet(network))
            for server in self.servers:
                answer = raw.dns_a(host, server)
                if answer:
                    addr, ttl = answer
                    self.cache[key] = (addr, time.monotonic() + ttl)
                    self.last_method = "L2 raw"
                    return addr
        # Still bypass the platform DNS resolver when the L2 driver or privileges
        # are unavailable. UDP is bound to the selected interface's IPv4.
        for server in self.servers:
            try:
                answer = udp_dns_a(host, server, network.ipv4 if network else "")
                if answer:
                    addr, ttl = answer
                    self.cache[key] = (addr, time.monotonic() + ttl)
                    self.last_method = "direct UDP"
                    return addr
            except (OSError, ValueError):
                pass
        # Normal DNS is a fallback when raw sockets are unsupported, lack privileges,
        # the campus DNS servers are unreachable, or lack a valid A answer.
        addresses = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        addr = addresses[0][4][0]
        self.cache[key] = (addr, time.monotonic() + 45)
        self.last_method = "system DNS"
        return addr


class _DirectSocketMixin:
    connect_ip: str
    network: Network | None

    def _dial(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            if self.network:
                sock.bind((self.network.ipv4, 0))
                if IS_LINUX and hasattr(socket, "SO_BINDTODEVICE"):
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                        self.network.name.encode() + b"\x00")
                    except OSError as exc:
                        # A fixed source IPv4 still prevents accidental source switching.
                        if exc.errno not in (errno.EPERM, errno.EACCES, errno.ENOPROTOOPT):
                            raise
            sock.connect((self.connect_ip, self.port))
            return sock
        except Exception:
            sock.close()
            raise


class DirectHTTPConnection(_DirectSocketMixin, http.client.HTTPConnection):
    def connect(self):
        self.sock = self._dial()


class DirectHTTPSConnection(_DirectSocketMixin, http.client.HTTPSConnection):
    def connect(self):
        raw_sock = self._dial()
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


@dataclass
class HTTPResult:
    status: int
    body: bytes
    location: str
    url: str


class HTTPTransport:
    def __init__(self, resolver: Resolver, timeout: float = 3.0):
        self.resolver = resolver
        self.timeout = timeout

    def request(self, url: str, network: Network | None,
                method: str = "GET", fields: dict | None = None,
                headers: dict | None = None) -> HTTPResult:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("unsupported or unsafe URL")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        dest = self.resolver.resolve(parts.hostname, network)
        cls = DirectHTTPSConnection if parts.scheme == "https" else DirectHTTPConnection
        conn = cls(parts.hostname, port=port, timeout=self.timeout)
        conn.connect_ip, conn.network = dest, network
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        body = urlencode(fields).encode("utf-8") if fields is not None else None
        h = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        if headers:
            h.update(headers)
        if fields is not None:
            h.setdefault("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        try:
            conn.request(method, path, body=body, headers=h)
            res = conn.getresponse()
            # Bounded read; neither a hostile portal nor an endpoint should exhaust RAM.
            payload = res.read(MAX_HTTP_BYTES)
            return HTTPResult(res.status, payload,
                              res.getheader("Location", ""), url)
        finally:
            conn.close()


def windows_dpapi(data: bytes, encrypt: bool) -> bytes:
    """Protect credentials with current Windows user's DPAPI account context."""
    if os.name != "nt":
        raise OSError("DPAPI only available on Windows")

    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]

    raw = ctypes.create_string_buffer(data)
    blob = Blob(len(data), ctypes.cast(raw, ctypes.c_void_p))
    result = Blob()
    crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    localfree = ctypes.WinDLL("kernel32.dll").LocalFree
    localfree.argtypes = [ctypes.c_void_p]
    localfree.restype = ctypes.c_void_p
    if encrypt:
        crypt32.CryptProtectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_wchar_p,
                                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_uint32, ctypes.POINTER(Blob)]
        crypt32.CryptProtectData.restype = ctypes.c_int
        ok = crypt32.CryptProtectData(ctypes.byref(blob), "UPC account", None, None,
                                      None, 0, ctypes.byref(result))
    else:
        crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p,
                                                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                ctypes.c_uint32, ctypes.POINTER(Blob)]
        crypt32.CryptUnprotectData.restype = ctypes.c_int
        ok = crypt32.CryptUnprotectData(ctypes.byref(blob), None, None, None,
                                        None, 0, ctypes.byref(result))
    if not ok:
        raise OSError(f"Windows DPAPI 操作失败 (WinError {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        localfree(result.data)


class Config:
    def __init__(self, path: Path):
        self.path = path
        self.legacy_path = Path.home() / ".upc"
        self.user = ""
        self.password = ""
        self.service = ""

    def load(self) -> bool:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("invalid config")
            self.user = str(data["user"])
            if os.name == "nt" and "password_dpapi" in data:
                blob = base64.b64decode(str(data["password_dpapi"]), validate=True)
                self.password = windows_dpapi(blob, False).decode("utf-8")
            else:
                self.password = str(data["password"])
            self.service = str(data.get("service", ""))
            if os.name == "nt" and "password_dpapi" not in data:
                # Migrate the earlier plaintext Windows config into DPAPI.
                self.save()
            return bool(self.user and self.password)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
            return False
        # Compatible migration from the original ~/.upc (password base64 encoded).
        try:
            values = self.legacy_path.read_text(encoding="utf-8").split()
            if len(values) < 2:
                return False
            self.user = values[0]
            self.password = base64.b64decode(values[1], validate=True).decode("utf-8")
            self.service = values[2] if len(values) > 2 else ""
            self.save()
            return True
        except (OSError, ValueError, UnicodeError, IndexError):
            return False

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                data = {"user": self.user, "service": self.service}
                if os.name == "nt":
                    data["password_dpapi"] = base64.b64encode(
                        windows_dpapi(self.password.encode("utf-8"), True)).decode("ascii")
                else:
                    data["password"] = self.password
                json.dump(data, f, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.path)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        finally:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass


def approved_portal(url: str, explicitly_trusted: str = "") -> bool:
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if parts.username or parts.password:
            return False
        if explicitly_trusted:
            trusted = urlsplit(explicitly_trusted)
            if parts.scheme == trusted.scheme and parts.netloc.lower() == trusted.netloc.lower():
                return True
        host = parts.hostname.lower().rstrip(".")
        return host in PORTAL_HOSTS
    except ValueError:
        return False


def extract_portal_redirect(response: HTTPResult, explicit: str = "") -> str:
    """Only follow/capture allowlisted portal endpoints; never use random 30x hosts."""
    if response.status in (301, 302, 303, 307, 308) and response.location:
        candidate = urljoin(response.url, response.location.strip())
        if approved_portal(candidate, explicit):
            return candidate
    body = html.unescape(response.body.decode("utf-8", errors="replace"))
    if not any(x in body.lower() for x in ("eportal", "wlanuserip", "wlanacip")):
        return ""
    # Canonical URL extraction from captive-portal HTML / JS.
    candidates = re.findall(r"https?://[^\s\"'<>\\]+", body, flags=re.I)
    for value in candidates:
        candidate = value.rstrip(");,]")
        if approved_portal(candidate, explicit) and ("eportal" in candidate.lower() or "wlan" in candidate.lower()):
            return candidate
    return ""


def parse_login_result(body: bytes) -> tuple[str, str]:
    """Strict JSON parsing: substring 'success' alone is not evidence of login."""
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeError):
        return "unknown", "认证接口返回非 JSON"
    if not isinstance(data, dict):
        return "unknown", "认证接口返回格式不正确"
    result = str(data.get("result", "")).lower().strip()
    detail = str(data.get("message") or data.get("msg") or
                 data.get("resultDescribe") or data.get("reason") or "")[:160]
    if result in {"success", "ok", "login_ok"}:
        return "success", detail
    return "failure", detail or f"result={result or 'empty'}"


class Watchdog:
    def __init__(self, args):
        self.args = args
        self.config = Config(Path(args.config).expanduser())
        self.resolver = Resolver()
        self.http = HTTPTransport(self.resolver, timeout=args.timeout)
        self.stop = threading.Event()
        self.pause = threading.Event()
        self.config_lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.portal_url = args.portal_url or ""
        self.current_network: Network | None = None
        self.state = "STARTING"
        self.next_login = 0.0
        self.delay = 10
        self.blocked_credentials = False
        self.last_alive_log = 0.0
        self.network_checked_at = 0.0
        self.last_dns_method = ""
        self.pending_auth_user = ""
        self.pending_auth_at = 0.0
        self.pending_auth_warned = False
        self.last_probe_evidence = ""
        self.terminal = getattr(sys.stdout, "isatty", lambda: False)()
        self.color_enabled = not getattr(args, "no_color", False) and supports_ansi_color()
        self.heartbeat_enabled = not getattr(args, "no_heartbeat", False)
        self.heartbeat_printing = False
        self.heartbeat_width = 0

    def _clear_heartbeat(self):
        """Called while holding print_lock."""
        if self.heartbeat_printing:
            if self.color_enabled:
                sys.stdout.write("\r\033[K")
            else:
                sys.stdout.write("\r" + " " * self.heartbeat_width + "\r")
            self.heartbeat_printing = False
            self.heartbeat_width = 0

    def log(self, message: str, level: str = "*", inline: bool = False):
        """Colored, thread-safe [HH:MM:SS] [+] messages; TTY heartbeat in place."""
        if level not in LOG_COLORS:
            level = "*"
        timestamp = time.strftime("[%H:%M:%S]", time.localtime())
        mark = f"[{level}]"
        if self.color_enabled:
            mark = f"{LOG_COLORS[level]}{mark}{COLOR_RESET}"
        message = f"{timestamp} {mark} {message}"
        with self.print_lock:
            self._clear_heartbeat()
            if inline and self.terminal:
                sys.stdout.write("\r" + ("\033[K" if self.color_enabled else "") + message)
                sys.stdout.flush()
                self.heartbeat_printing = True
                self.heartbeat_width = len(message)
            else:
                print(message, flush=True)

    def _reset_pending_auth(self):
        self.pending_auth_user = ""
        self.pending_auth_at = 0.0
        self.pending_auth_warned = False

    def _network_summary(self) -> str:
        net = self.current_network
        return f"网卡: {net.name} / IPv4: {net.ipv4}" if net else "网卡: 未知"

    def setup(self):
        if not sys.stdin.isatty():
            self.log("缺少认证配置；非交互环境请先在终端运行一次配置程序。", "-")
            return
        self.pause.set()
        self.log("进入账号配置模式（Ctrl+C 取消）", "*")
        try:
            print("--- 修改校园网账号（Ctrl+C 取消）---", flush=True)
            user = input("账号: ").strip()
            if not user:
                self.log("账号为空，保持现有配置", "!")
                return
            password = getpass.getpass("密码（输入时不回显）: ")
            if not password:
                self.log("密码为空，保持现有配置", "!")
                return
            print("运营商: [1] 校园网 [2] 电信 [3] 联通 [4] 移动")
            choice = input("选择 [1]: ").strip() or "1"
            if choice not in SERVICES:
                self.log("运营商选项无效，保持现有配置", "-")
                return
            with self.config_lock:
                self.config.user, self.config.password = user, password
                self.config.service = SERVICES[choice]
                self.config.save()
                self.blocked_credentials = False
                self.next_login = 0.0
                self.delay = 10
                self._reset_pending_auth()
            protection = "Windows DPAPI 加密" if os.name == "nt" else "权限 0600，仅限制本地访问（非加密）"
            self.log(f"账号 {user} 的认证配置已保存（{protection}）", "+")
        except (KeyboardInterrupt, EOFError):
            self.log("取消修改", "!")
        finally:
            self.pause.clear()

    def network_update(self) -> Network | None:
        now = time.monotonic()
        # PowerShell/CIM is relatively expensive. Avoid a subprocess on every heartbeat.
        if os.name == "nt" and now - self.network_checked_at < 10:
            return self.current_network
        self.network_checked_at = now
        network = (windows_network(self.args.iface) if os.name == "nt" else
                   linux_network(self.args.iface))
        if network != self.current_network:
            if self.current_network is not None:
                self.log("网络接口/IPv4/默认路由变化；清空 DNS 缓存并重新发现 Portal", "!")
            if network is not None and self.args.debug:
                self.log(f"网卡 {network.name}, IP {network.ipv4}, 网关 {network.gateway}", "*")
            self.current_network = network
            self.resolver.clear()
            if not self.args.portal_url:
                self.portal_url = ""
            self.next_login = 0.0
            self.delay = 10
            self._reset_pending_auth()
        return network

    def check_link(self, network: Network | None) -> bool:
        if os.name == "nt":
            # Do not fall back to arbitrary VPN/other routes if the chosen default
            # interface disappears. Wait until a usable route comes back.
            return network is not None
        if not IS_LINUX:
            return True
        if network is None:
            return False
        try:
            state = (Path("/sys/class/net") / network.name / "operstate").read_text().strip()
            if state in ("down", "lowerlayerdown", "notpresent"):
                return False
        except OSError:
            pass
        return True

    def probe(self, network: Network | None) -> tuple[str, str]:
        self.last_probe_evidence = ""
        captive = ""
        successes = 0
        for url, code, expected in CHECKS:
            try:
                response = self.http.request(url, network)
                candidate = extract_portal_redirect(response, self.args.portal_url or "")
                if candidate:
                    captive = candidate
                    break
                # Never accept generic HTTP 200 or arbitrary 302 as proof of internet.
                body = response.body.strip()
                if urlsplit(url).hostname == "www.msftconnecttest.com":
                    valid = body == expected
                else:
                    valid = (body.lower() == expected.lower() or
                             body.lower() == b"<html><head><title>success</title></head><body>success</body></html>")
                if response.status == code and valid:
                    successes += 1
            except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
                if self.args.debug:
                    self.log(f"探测 {urlsplit(url).hostname} 失败：{type(exc).__name__}: {exc}", "!")
        if captive:
            return "CAPTIVE", captive
        if successes == len(CHECKS):
            self.last_probe_evidence = "双站点 HTTP 连通性检查通过"
            return "ONLINE", ""
        # Some campus captive portals whitelist Windows' connectivity probe.
        # A single HTTP success is not enough; genuine certificate-validated
        # HTTPS to a separate public host is stronger evidence of connectivity.
        try:
            https_result = self.http.request("https://www.baidu.com/", network, "HEAD")
            if 200 <= https_result.status < 500:
                self.last_probe_evidence = "HTTPS 证书校验通过"
                return "ONLINE", ""
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
            if self.args.debug:
                self.log(f"HTTPS 校验失败：{type(exc).__name__}: {exc}", "!")
        # Last resort: a direct IPv4 HTTP request can elicit a portal redirect
        # even when DNS interception prevents resolving both check hosts.
        try:
            response = self.http.request("http://1.1.1.1/", network)
            portal = extract_portal_redirect(response, self.args.portal_url or "")
            if portal:
                return "CAPTIVE", portal
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            pass
        return "UNKNOWN", ""

    def login(self, network: Network | None) -> bool:
        if not self.portal_url or not approved_portal(self.portal_url, self.args.portal_url or ""):
            self.log("没有可信 Portal 地址，拒绝发送密码", "-")
            return False
        if self.blocked_credentials or time.monotonic() < self.next_login:
            return False
        with self.config_lock:
            if not self.config.user or not self.config.password:
                self.log("缺少校园网账号，按 x 配置", "-")
                self.next_login = time.monotonic() + 60
                return False
            user, password, service = self.config.user, self.config.password, self.config.service
        parts = urlsplit(self.portal_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        endpoint = urljoin(origin, LOGIN_PATH)
        # No requirement to follow redirect; the POST response is only a hint.
        fields = {"userId": user, "password": password,
                  "service": service, "queryString": parts.query,
                  "operatorPwd": "", "operatorUserId": "", "validcode": "",
                  "passwordEncrypt": "false"}
        try:
            response = self.http.request(
                endpoint, network, "POST", fields,
                headers={"Origin": origin, "Referer": self.portal_url,
                         "Accept": "application/json, text/plain, */*"})
            if response.status in (301, 302, 303, 307, 308):
                self.log(f"认证 POST 返回 HTTP {response.status}；尚未确认成功，将重新探测", "!")
                self.resolver.clear()  # Redirect may coincide with DHCP/DNS state transition.
                return self._retry("认证接口发生跳转")
            if response.status != 200:
                return self._retry(f"认证 HTTP {response.status}")
            outcome, detail = parse_login_result(response.body)
            if outcome == "success":
                # The gateway may accept a login while the external path remains blocked.
                # Show two explicit phases; only the ONLINE probe confirms connectivity.
                self.pending_auth_user = user
                self.pending_auth_at = time.monotonic()
                self.pending_auth_warned = False
                suffix = f"；网关信息：{detail}" if detail else ""
                self.log(f"网关已返回认证成功（账号: {user}）{suffix}；正在复核外网连通性...", "*")
                self.resolver.clear()  # Captive DNS responses must not survive login.
                self.next_login = time.monotonic() + 40  # Avoid duplicate POST storms.
                self.delay = 10
                return True
            if outcome == "failure" and any(term in detail for term in (
                    "账号或密码错误", "密码错误", "用户不存在", "账号不存在", "用户或密码", "用户名或密码")):
                self.blocked_credentials = True
                self._reset_pending_auth()
                self.log(f"Portal 拒绝凭据：{detail}；暂停重试，请按 x 修改配置", "-")
                return False
            return self._retry(f"认证未成功：{detail}")
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
            return self._retry(f"认证网络异常：{type(exc).__name__}: {exc}")

    def _retry(self, reason: str) -> bool:
        self._reset_pending_auth()
        delay = min(180, self.delay) + random.uniform(0, 2)
        self.next_login = time.monotonic() + delay
        self.delay = min(self.delay * 2, 180)
        self.log(f"{reason}；约 {int(delay)} 秒后可重试", "-")
        return False

    def run_once(self):
        network = self.network_update()
        if not self.check_link(network):
            self._set_state("LINK_DOWN")
            return
        state, portal = self.probe(network)
        if self.args.debug and self.resolver.last_method != self.last_dns_method:
            self.last_dns_method = self.resolver.last_method
            if self.last_dns_method:
                self.log(f"DNS 使用方式：{self.last_dns_method}", "*")
        if portal and not self.args.portal_url:
            self.portal_url = portal
        self._set_state(state)
        if state == "ONLINE":
            self.next_login = 0.0
            self.delay = 10
            if self.heartbeat_enabled and self.terminal and not self.pause.is_set():
                with self.config_lock:
                    user = self.config.user or "未配置"
                self.log(f"外网在线 | 账号: {user} | {self._network_summary()}", "+", inline=True)
        elif state == "CAPTIVE" and not self.pause.is_set():
            self._warn_if_auth_unconfirmed()
            self.login(network)
        elif state == "UNKNOWN":
            self._warn_if_auth_unconfirmed()
            # Do not POST credentials just because one external endpoint timed out.

    def _warn_if_auth_unconfirmed(self):
        if (self.pending_auth_user and not self.pending_auth_warned and
                time.monotonic() - self.pending_auth_at >= 25):
            self.pending_auth_warned = True
            self.log("网关曾返回认证成功，但外网尚未通过检测；继续监控并按重试间隔恢复", "!")

    def _set_state(self, state: str):
        if state == self.state:
            if state == "ONLINE" and time.monotonic() - self.last_alive_log >= 120:
                self.log(f"外网保持连通 | {self._network_summary()}", "+")
                self.last_alive_log = time.monotonic()
            return

        previous = self.state
        self.state = state
        if state == "ONLINE":
            now = time.monotonic()
            info = self._network_summary()
            evidence = self.last_probe_evidence or "外网连通性检查通过"
            if self.pending_auth_user and now - self.pending_auth_at <= 180:
                self.log(
                    f"认证成功！账号: {self.pending_auth_user} | {info} | 验证: {evidence}", "+")
            elif previous in ("LINK_DOWN", "UNKNOWN", "CAPTIVE"):
                self.log(f"网络已自动恢复！{info} | 验证: {evidence}", "+")
            else:
                self.log(f"网络已连接！{info} | 验证: {evidence}", "+")
            self._reset_pending_auth()
            self.last_alive_log = now
        elif state == "LINK_DOWN":
            self._reset_pending_auth()
            self.log("网卡或默认路由不可用，暂停登录，自动等待网络恢复", "-")
        elif state == "CAPTIVE":
            if previous == "ONLINE":
                self.log("检测到掉线：网络被校园认证页面拦截，将自动重新登录", "-")
            else:
                self.log("检测到校园认证页面，准备自动登录", "*")
        elif state == "UNKNOWN":
            if previous == "ONLINE":
                self.log("外网连接异常，暂不能确认是否需要认证；持续检测避免误登录", "-")
            else:
                self.log("外网状态暂不确定，继续探测（不会因普通超时反复登录）", "!")
        else:
            self.log(f"网络状态更新: {previous} -> {state}", "*")

    def monitor(self):
        while not self.stop.is_set():
            if self.pause.is_set():
                self.stop.wait(0.25)
                continue
            try:
                self.run_once()
            except Exception as exc:
                self.log(f"监控循环异常（未退出）：{type(exc).__name__}: {exc}", "-")
                if self.args.debug:
                    import traceback
                    traceback.print_exc()
            if self.args.once:
                return
            self.stop.wait(12 if self.state == "ONLINE" else 4)

    def start(self):
        if self.args.portal_url and not approved_portal(self.args.portal_url, self.args.portal_url):
            raise ValueError("--portal-url 必须是有效的 HTTP(S) 地址")
        if not self.config.load():
            self.setup()
            if not self.config.load():
                raise SystemExit("没有可用配置。请在交互终端配置后重试。")
        self.log("认证守护进程启动：优先原始以太网 ARP/DNS；HTTP/TLS 仍使用 TCP", "+")
        if IS_LINUX and os.geteuid() != 0:
            self.log("提示：当前非 root。若无 CAP_NET_RAW，将使用系统 DNS 作为回退", "!")
        if os.name == "nt":
            try:
                npcap_library()
                self.log("已检测到 Npcap 库，将优先尝试原始二层报文（需要网卡抓包权限）", "+")
            except OSError as exc:
                self.log(f"Npcap 不可用，回退到直接 UDP/系统 DNS：{exc}", "!")
        if self.args.once:
            self.monitor()
            return
        worker = threading.Thread(target=self.monitor, daemon=True)
        worker.start()
        try:
            if sys.stdin.isatty():
                self.log("输入 x 回车可更换账号；Ctrl+C 退出", "*")
                while not self.stop.is_set():
                    line = sys.stdin.readline()
                    if not line:
                        break
                    if line.strip().lower() == "x":
                        self.setup()
            else:
                while not self.stop.wait(1):
                    pass
        except KeyboardInterrupt:
            self.log("收到退出指令", "!")
        finally:
            self.stop.set()
            worker.join(timeout=5)


def main():
    p = argparse.ArgumentParser(description="UPC 校园网可靠自动认证（Linux AF_PACKET / Windows Npcap）")
    p.add_argument("--iface", help="指定联网网卡（Linux: enp3s0；Windows: Wi-Fi 或接口索引）")
    p.add_argument("--config", default=str(Path.home() / ".upc.json"),
                   help="JSON 认证配置文件，自动兼容旧版 ~/.upc")
    p.add_argument("--portal-url", default="", help="显式可信的 Portal 重定向 URL")
    p.add_argument("--timeout", type=float, default=3.0, help="HTTP 超时秒数")
    p.add_argument("--once", action="store_true", help="仅检测并尝试一次认证")
    p.add_argument("--debug", action="store_true", help="打印网络诊断详情")
    p.add_argument("--no-color", action="store_true", help="关闭终端 ANSI 颜色（默认自动检测）")
    p.add_argument("--no-heartbeat", action="store_true", help="禁用终端单行实时在线心跳")
    args = p.parse_args()
    if args.timeout <= 0:
        p.error("--timeout 必须大于 0")
    Watchdog(args).start()


if __name__ == "__main__":
    main()
