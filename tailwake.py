#!/usr/bin/env python3
"""TailWake: wake your computers from anywhere over Tailscale.

A small background app with a tray icon. It serves a phone-friendly page to your Tailscale devices; tap Wake and
it sends a Wake-on-LAN magic packet on its own local network.

Standard-library Python 3.10+. The tray icon needs `pystray` and `Pillow` (the installers set them up); without them
TailWake runs without an icon. The settings window needs tkinter.

    tailwake                 start in the background (or open settings if it is already running)
    tailwake settings        open the settings window
    tailwake stop | restart | status
    tailwake wake [NAME]     wake a device from the command line
    tailwake help            all commands

https://github.com/onetrickpony1/tailwake  -  GNU GPL v3.0 or later
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = "TailWake"
VERSION = "1.1.0"
REPO = "https://github.com/onetrickpony1/tailwake"
DEFAULT_PORT = 8002
MIN_PORT = 1024                   # lower ports need admin/root rights on Linux and macOS
WAKE_WATCH_SECONDS = 180          # after a wake, keep checking this long to report when it comes up
VIEW_WINDOW_SECONDS = 30          # the page counts as "open" this long after its last status request
SWEEP_EVERY_SECONDS = 120         # at most one local-network sweep per this many seconds
PROBE_PORTS = (445, 22, 3389, 139, 80, 443, 5900, 548, 62078, 8080)

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
NO_WINDOW = 0x08000000 if IS_WIN else 0          # CREATE_NO_WINDOW: no console flashes under pythonw

log = logging.getLogger("tailwake")


# --------------------------------------------------------------------------------------------------------- paths

def config_dir() -> str:
    if os.environ.get("TAILWAKE_HOME"):
        return os.environ["TAILWAKE_HOME"]
    if IS_WIN:
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming"), APP)
    if IS_MAC:
        return os.path.expanduser("~/Library/Application Support/TailWake")
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "tailwake")


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def state_path() -> str:
    return os.path.join(config_dir(), "running.json")


def log_path() -> str:
    return os.path.join(config_dir(), "tailwake.log")


def script_path() -> str:
    return os.path.abspath(__file__)


def gui_python() -> str:
    """The interpreter to use for windowed/background launches (pythonw.exe on Windows: no console window)."""
    exe = sys.executable
    if IS_WIN:
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(w):
            return w
    return exe


def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def read_json(path: str, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# -------------------------------------------------------------------------------------------------------- config

DEFAULTS = {
    "port": DEFAULT_PORT,
    "access": "tailscale",          # "tailscale": Tailscale devices only; "network": Tailscale + local network
    "password_hash": "",
    "password_salt": "",
    "background_checks": False,     # keep checking status when nobody is looking (pings can wake some PCs)
    "check_seconds": 15,
    "notifications": True,
    "devices": [],                  # {"id", "name", "mac", "ip", "broadcast"}
    "secret": "",
}


def load_config() -> dict:
    """The settings, with defaults filled in. Keys and device fields this version doesn't know are kept so that
    save_config writes them back. Devices whose MAC address doesn't parse are kept aside in "_invalid_devices"
    (saved again, never used)."""
    cfg = dict(DEFAULTS)
    data = read_json(config_path(), {})
    if isinstance(data, dict):
        cfg.update({k: v for k, v in data.items() if not k.startswith("_")})
    if not cfg["secret"]:
        cfg["secret"] = secrets.token_hex(16)
        save_config(cfg)
    devices, invalid = [], []
    for d in cfg.get("devices") or []:
        if isinstance(d, dict) and normalize_mac(str(d.get("mac") or "")):
            devices.append(dict(d, **{
                "id": str(d.get("id") or secrets.token_hex(4)),
                "name": str(d.get("name") or "Device").strip() or "Device",
                "mac": normalize_mac(str(d["mac"])),
                "ip": str(d.get("ip") or "").strip(),
                "broadcast": str(d.get("broadcast") or "").strip(),
            }))
        else:
            invalid.append(d)
    cfg["devices"] = devices
    cfg["_invalid_devices"] = invalid
    try:
        cfg["port"] = int(cfg["port"])
    except (TypeError, ValueError):
        cfg["port"] = DEFAULT_PORT
    try:
        cfg["check_seconds"] = max(5, int(cfg["check_seconds"]))
    except (TypeError, ValueError):
        cfg["check_seconds"] = 15
    if cfg["access"] not in ("tailscale", "network"):
        cfg["access"] = "tailscale"
    return cfg


def save_config(cfg: dict) -> None:
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    for k, v in DEFAULTS.items():
        out.setdefault(k, v)
    names = {str(d.get("name") or "").strip().lower() for d in cfg.get("devices") or [] if isinstance(d, dict)}
    out["devices"] = list(cfg.get("devices") or []) + [      # an unreadable device stays until one replaces it
        d for d in cfg.get("_invalid_devices") or []
        if not (isinstance(d, dict) and str(d.get("name") or "").strip().lower() in names)]
    write_json(config_path(), out)


def port_problem(port) -> str:
    """'' if `port` can be used for the web page, else why not."""
    if not isinstance(port, int) or not MIN_PORT <= port <= 65535:
        return "The port must be a number from %d to 65535." % MIN_PORT
    return ""


def hash_password(password: str, salt: str = "") -> tuple:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 200_000).hex()
    return digest, salt


def check_password(cfg: dict, password: str) -> bool:
    if not cfg.get("password_hash"):
        return True
    digest, _ = hash_password(password, cfg["password_salt"])
    return hmac.compare_digest(digest, cfg["password_hash"])


def set_password(cfg: dict, password: str) -> None:
    if password:
        cfg["password_hash"], cfg["password_salt"] = hash_password(password)
    else:
        cfg["password_hash"] = cfg["password_salt"] = ""


def ensure_network_password(cfg: dict) -> str:
    """Local-network access needs a password: make one if it is on without one. Returns the new password or ''."""
    if cfg.get("access") == "network" and not cfg.get("password_hash"):
        password = secrets.token_urlsafe(9)
        set_password(cfg, password)
        return password
    return ""


def find_device(cfg: dict, key: str):
    key = (key or "").strip().lower()
    for d in cfg["devices"]:
        if key in (d["id"].lower(), d["name"].lower()):
            return d
    mac = normalize_mac(key)
    for d in cfg["devices"]:
        if mac and d["mac"] == mac:
            return d
    return None


# ------------------------------------------------------------------------------------------------------- network

def run_quiet(cmd: list, timeout: float = 5.0) -> tuple:
    """Run a command without a console window. Returns (exit code, combined output); (-1, "") if it can't run."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           timeout=timeout, creationflags=NO_WINDOW)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def normalize_mac(text: str):
    """'00-1A-2B-3C-4D-5E', '0:1a:2b:3c:4d:5e', '001a.2b3c.4d5e', '9c6b00b322b4' -> '00:1a:2b:3c:4d:5e' (or None)."""
    s = (text or "").strip().lower()
    if not s:
        return None
    if re.fullmatch(r"[0-9a-f]{12}", s):
        parts = [s[i:i + 2] for i in range(0, 12, 2)]
    elif re.fullmatch(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", s):
        h = s.replace(".", "")
        parts = [h[i:i + 2] for i in range(0, 12, 2)]
    else:
        parts = re.split(r"[:\-\s]", s)
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return None
    return ":".join("%02x" % int(p, 16) for p in parts)


def magic_packet(mac: str) -> bytes:
    raw = bytes.fromhex(normalize_mac(mac).replace(":", ""))
    return b"\xff" * 6 + raw * 16


def is_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False


def local_ip_toward(dest: str = "192.0.2.1"):
    """The local IPv4 address the OS would use to reach `dest` (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest, 9))
        ip = s.getsockname()[0]
        return None if ip.startswith("0.") else ip
    except OSError:
        return None
    finally:
        s.close()


def subnet_24(ip: str):
    return ipaddress.ip_network(ip + "/24", strict=False)


def in_tailscale_range(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    if isinstance(a, ipaddress.IPv4Address):
        return a in ipaddress.ip_network("100.64.0.0/10")
    return a in ipaddress.ip_network("fd7a:115c:a1e0::/48")


def lan_ip_for(device: dict):
    """The local address used to reach a device's network (not a Tailscale address)."""
    ip = local_ip_toward(device["ip"]) if is_ipv4(device.get("ip", "")) else None
    if not ip or in_tailscale_range(ip):
        ip = local_ip_toward()
    if ip and in_tailscale_range(ip):
        return None
    return ip


def broadcast_targets(device: dict) -> list:
    targets = ["255.255.255.255"]
    lan = lan_ip_for(device)
    if lan:
        targets.append(str(subnet_24(lan).broadcast_address))
    if is_ipv4(device.get("ip", "")):
        targets.append(str(subnet_24(device["ip"]).broadcast_address))
        targets.append(device["ip"])          # unicast: works while the switch/ARP still knows the device
    if is_ipv4(device.get("broadcast", "")):
        targets.insert(0, device["broadcast"])
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def send_wake(device: dict) -> str:
    packet = magic_packet(device["mac"])
    targets = broadcast_targets(device)
    lan = lan_ip_for(device)
    sent = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if lan:
            try:
                s.bind((lan, 0))          # leave through the interface on the device's network
            except OSError:
                pass
        for t in targets:
            for port in (9, 7):
                try:
                    s.sendto(packet, (t, port))
                    sent.append("%s:%d" % (t, port))
                except OSError as e:
                    log.debug("wake send to %s:%d failed: %s", t, port, e)
    finally:
        s.close()
    if not sent:
        raise OSError("no network interface accepted the wake packet")
    log.info("Wake packet for %s (%s) sent to %s", device["name"], device["mac"], ", ".join(sent))
    return "Wake packet sent to %s." % device["name"]


def ping(ip: str) -> bool:
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    code, out = run_quiet(cmd, timeout=3)
    return code == 0 and "ttl=" in out.lower()


def tcp_answers(ip: str, timeout: float = 0.6) -> bool:
    """True if any probe port answers - accepting OR refusing both prove the host is up."""
    result = threading.Event()

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((ip, port))
            if code == 0 or code in (111, 61, 10061):      # connected, or ECONNREFUSED (Linux, macOS, Windows)
                result.set()
        except OSError:
            pass
        finally:
            s.close()

    threads = [threading.Thread(target=probe, args=(p,), daemon=True) for p in PROBE_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 0.3)
    return result.is_set()


def poke(ip: str) -> None:
    """Send one tiny UDP datagram to the discard port: makes the OS resolve (and refresh) the address table entry."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\0", (ip, 9))
        s.close()
    except OSError:
        pass


_SWEEP_LOCK = threading.Lock()
_last_sweep = {}


def sweep(lan_ip: str, force: bool = False) -> bool:
    """Poke every address in the /24 around `lan_ip` so the address table fills up. Rate limited."""
    if not lan_ip:
        return False
    net = subnet_24(lan_ip)
    with _SWEEP_LOCK:
        if not force and time.time() - _last_sweep.get(str(net), 0) < SWEEP_EVERY_SECONDS:
            return False
        _last_sweep[str(net)] = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for host in net.hosts():
            if str(host) != lan_ip:
                try:
                    s.sendto(b"\0", (str(host), 9))
                except OSError:
                    pass
    finally:
        s.close()
    return True


# Neighbour (ARP) table. state: "ok" = confirmed recently, "stale" = known but not confirmed, "unknown" = listed but
# the OS doesn't say how fresh (macOS, old Linux). Entries that are incomplete/failed are left out.

def parse_ip_neigh(text: str) -> list:
    out = []
    for line in text.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s.*\blladdr\s+([0-9a-fA-F:]+)\s+(?:\w+\s+)*?([A-Z]+)\s*$", line.strip())
        if not m:
            continue
        state = m.group(3)
        if state in ("FAILED", "INCOMPLETE", "NONE"):
            continue
        out.append((m.group(1), normalize_mac(m.group(2)),
                    "ok" if state in ("REACHABLE", "PERMANENT", "NOARP") else "stale"))
    return out


def parse_proc_arp(text: str) -> list:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[2] != "0x0":
            out.append((f[0], normalize_mac(f[3]), "unknown"))
    return out


def parse_arp_a(text: str) -> list:
    """`arp -an` (macOS/BSD) and `arp -a` (Windows)."""
    out = []
    for line in text.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"(?<![0-9a-fA-F:\-])([0-9a-fA-F]{1,2}([:\-])(?:[0-9a-fA-F]{1,2}\2){4}[0-9a-fA-F]{1,2})(?![0-9a-fA-F:\-])",
                        line)
        if ip and mac and "incomplete" not in line.lower():
            out.append((ip.group(1), normalize_mac(mac.group(1)), "unknown"))
    return out


def parse_netsh(text: str) -> list:
    """`netsh interface ipv4 show neighbors` (Windows) - has the entry state."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S.*?)\s*$", line)
        if not m:
            continue
        kind = m.group(3).lower()
        if kind in ("unreachable", "incomplete"):
            continue
        if kind in ("reachable", "permanent"):
            state = "ok"
        elif kind in ("stale", "delay", "probe"):
            state = "stale"
        else:
            state = "unknown"          # a translated Windows: can't tell, count it as present
        out.append((m.group(1), normalize_mac(m.group(2)), state))
    return out


def neighbours() -> list:
    """[(ip, mac, state)] for real unicast devices."""
    rows = []
    if IS_WIN:
        code, out = run_quiet(["netsh", "interface", "ipv4", "show", "neighbors"], timeout=4)
        rows = parse_netsh(out) if code == 0 else []
        if not rows:
            rows = parse_arp_a(run_quiet(["arp", "-a"], timeout=4)[1])
    elif IS_MAC or not sys.platform.startswith("linux"):
        rows = parse_arp_a(run_quiet(["arp", "-an"], timeout=4)[1])
    else:
        code, out = run_quiet(["ip", "-4", "neigh", "show"], timeout=4)
        rows = parse_ip_neigh(out) if code == 0 else []
        if code != 0:
            try:
                with open("/proc/net/arp") as f:
                    rows = parse_proc_arp(f.read())
            except OSError:
                rows = []
    clean = []
    for ip, mac, state in rows:
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or int(mac[:2], 16) & 1:
            continue
        if ip.endswith(".255") or ip.startswith(("224.", "239.", "255.")):
            continue
        clean.append((ip, mac, state))
    return clean


def mac_for_ip(ip: str):
    poke(ip)
    ping(ip)
    for row_ip, mac, _ in neighbours():
        if row_ip == ip:
            return mac
    return None


def reverse_names(ips: list, wait: float = 2.0) -> dict:
    names = {}

    def look(ip):
        try:
            names[ip] = socket.gethostbyaddr(ip)[0]
        except OSError:
            pass

    threads = [threading.Thread(target=look, args=(ip,), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    end = time.time() + wait
    for t in threads:
        t.join(max(0.0, end - time.time()))
    return dict(names)


def scan_network() -> list:
    """Find devices on the local network: [(ip, mac, name, state)]."""
    lan = local_ip_toward()
    if lan and in_tailscale_range(lan):
        lan = None
    if lan:
        sweep(lan, force=True)
        time.sleep(2.5)
    rows = sorted(neighbours(), key=lambda r: tuple(int(x) for x in r[0].split(".")))
    names = reverse_names([r[0] for r in rows])
    return [(ip, mac, names.get(ip, ""), state) for ip, mac, state in rows]


_confirmed = {}          # mac -> last time the OS confirmed its address table entry


def _live_entry(table: list, mac: str):
    """The address-table row for `mac` if it counts as live. A "stale" entry counts if it was confirmed in the last
    two minutes (Linux and Windows only re-confirm entries every 15-45 s, so this stops status flapping)."""
    for row in table:
        if row[1] != mac:
            continue
        if row[2] == "ok":
            _confirmed[mac] = time.time()
            return row
        if row[2] == "unknown" or (row[2] == "stale" and time.time() - _confirmed.get(mac, 0) < 120):
            return row
    return None


def check_device(device: dict) -> dict:
    """Is the device on? Ping, then TCP probes, then the address table (a recent entry for its MAC address)."""
    ip, mac = device.get("ip", ""), device["mac"]
    now = time.strftime("%H:%M:%S")
    if is_ipv4(ip):
        found = {}
        t1 = threading.Thread(target=lambda: found.__setitem__("ping", ping(ip)), daemon=True)
        t2 = threading.Thread(target=lambda: found.__setitem__("tcp", tcp_answers(ip)), daemon=True)
        t1.start(), t2.start()
        t1.join(4), t2.join(4)
        if found.get("ping") or found.get("tcp"):
            return {"online": True, "seen_ip": ip, "checked": now,
                    "detail": "Online. It answered at %s." % ip}
        poke(ip)
    table = neighbours()
    hit = _live_entry(table, mac)
    if not hit and sweep(lan_ip_for(device)):
        time.sleep(1.5)
        table = neighbours()
        hit = _live_entry(table, mac)
    if hit:
        where = hit[0]
        if is_ipv4(ip) and where != ip:
            detail = "Online. Its MAC address is at %s (not the saved %s)." % (where, ip)
        elif not is_ipv4(ip):
            detail = "Online. Its MAC address is active at %s." % where
        else:
            detail = "Online. It doesn't answer pings, but its MAC address is active at %s." % where
        return {"online": True, "seen_ip": where, "checked": now, "detail": detail}
    if is_ipv4(ip):
        detail = "Offline. Nothing answered at %s and its MAC address isn't active on the network." % ip
    else:
        detail = "Offline. Its MAC address isn't active on the network. (Add its IP address for better checks.)"
    return {"online": False, "seen_ip": "", "checked": now, "detail": detail}


# ----------------------------------------------------------------------------------------------------- tailscale

def tailscale_cli():
    found = shutil.which("tailscale")
    if found:
        return found
    candidates = []
    if IS_WIN:
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), r"C:\Program Files"):
            if base:
                candidates.append(os.path.join(base, "Tailscale", "tailscale.exe"))
    elif IS_MAC:
        candidates += ["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale",
                       "/opt/homebrew/bin/tailscale"]
    else:
        candidates += ["/usr/bin/tailscale", "/usr/sbin/tailscale", "/usr/local/bin/tailscale", "/snap/bin/tailscale"]
    return next((c for c in candidates if os.path.exists(c)), None)


def tailscale_info() -> dict:
    """{installed, connected, ip, dns, state}. Works without the CLI too (finds the 100.x address)."""
    info = {"installed": False, "connected": False, "ip": "", "dns": "", "state": ""}
    cli = tailscale_cli()
    if cli:
        info["installed"] = True
        code, out = run_quiet([cli, "status", "--json"], timeout=5)
        try:
            data = json.loads(out[out.index("{"):]) if "{" in out else {}
        except ValueError:
            data = {}
        info["state"] = data.get("BackendState", "")
        me = data.get("Self") or {}
        info["dns"] = (me.get("DNSName") or "").rstrip(".")
        for addr in me.get("TailscaleIPs") or []:
            if is_ipv4(addr):
                info["ip"] = addr
                break
        info["connected"] = info["state"] == "Running"
    if not info["ip"]:
        ip = local_ip_toward("100.100.100.100")
        if ip and in_tailscale_range(ip):
            info["ip"] = ip
            info["connected"] = True
            info["installed"] = True
    if not info["connected"]:
        info["ip"] = ""
    return info


SERVE_HTTPS_PORTS = (443, 8443, 10000)          # the HTTPS ports Tailscale Serve can use


def serve_config():
    """Tailscale Serve's current settings (`tailscale serve status --json`), or None if they can't be read."""
    cli = tailscale_cli()
    if not cli:
        return None
    code, out = run_quiet([cli, "serve", "status", "--json"], timeout=10)
    if code != 0:
        return None
    if "{" not in out:
        return {}                                   # nothing is being served
    try:
        data = json.loads(out[out.index("{"):])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _local_port(target: str):
    """'http://127.0.0.1:8002' or 'localhost:8002' -> 8002; anything that isn't a local HTTP server -> None."""
    u = urllib.parse.urlsplit(target if "://" in target else "http://" + target)
    try:
        port = u.port
    except ValueError:
        return None
    if u.scheme == "http" and (u.hostname or "").lower() in ("127.0.0.1", "localhost", "::1"):
        return port or 80
    return None


def serve_handlers(conf: dict) -> list:
    """Every HTTPS handler in a Serve config: [{"host", "https_port", "path", "target", "local_port"}]."""
    out = []
    for hostport, web in sorted(((conf or {}).get("Web") or {}).items()):
        host, _, p = hostport.rpartition(":")
        try:
            https_port = int(p)
        except ValueError:
            continue
        for path, h in sorted(((web or {}).get("Handlers") or {}).items()):
            h = h or {}
            target = h.get("Proxy") or ""
            out.append({"host": host, "https_port": https_port, "path": path,
                        "target": target or ("files" if h.get("Path") else "text"),
                        "local_port": _local_port(target) if target else None})
    return out


def serve_url(host: str, https_port: int, path: str = "/") -> str:
    return "https://%s%s%s" % (host, "" if https_port == 443 else ":%d" % https_port, path)


def serve_urls(conf: dict, port: int) -> list:
    """The https://...ts.net addresses that currently forward to TailWake on `port`."""
    return [serve_url(h["host"], h["https_port"]) for h in serve_handlers(conf)
            if h["local_port"] == port and h["path"] == "/"]


def serve_free_port(conf: dict, port: int):
    """The first HTTPS port where TailWake can go at "/" without replacing something else, or None."""
    handlers = serve_handlers(conf)
    for hp in SERVE_HTTPS_PORTS:
        tcp = ((conf or {}).get("TCP") or {}).get(str(hp)) or {}
        if tcp and not tcp.get("HTTPS"):
            continue                                # a raw TCP forwarder uses this port
        if all(h["local_port"] == port for h in handlers if h["https_port"] == hp and h["path"] == "/"):
            return hp
    return None


def _serve_failed(code: int, out: str) -> str:
    out = out.strip()
    if code == -1 and not out:
        out = "Tailscale did not answer in time. If it printed a link to enable HTTPS, open the Tailscale admin page."
    if "access denied" in out.lower() or "operator" in out.lower():
        out += "\n\nOn Linux, allow your user once with:\n  sudo tailscale set --operator=$USER"
    return out or "Tailscale Serve failed (exit code %d)." % code


def tailscale_serve(port: int, on: bool) -> tuple:
    """Turn the tailnet-only HTTPS address (Tailscale Serve) on or off. Returns (ok, message).
    Only TailWake's own handler is added or removed: other things served by Tailscale Serve are left alone."""
    cli = tailscale_cli()
    if not cli:
        return False, "The Tailscale command line tool was not found."
    conf = serve_config()
    if conf is None:
        return False, ("Couldn't read Tailscale Serve's current settings (`tailscale serve status --json`), so "
                       "nothing was changed. Is Tailscale running and up to date?")
    mine = [h for h in serve_handlers(conf) if h["local_port"] == port]
    if not on:
        if not mine:
            return True, "The HTTPS address is already off."
        for h in mine:
            code, out = run_quiet([cli, "serve", "--https=%d" % h["https_port"], "--set-path", h["path"], "off"],
                                  timeout=25)
            if code != 0:
                return False, _serve_failed(code, out)
        return True, "HTTPS address turned off. Anything else Tailscale Serve shares was left as it was."
    urls = serve_urls(conf, port)
    if urls:
        return True, "The HTTPS address is already on: " + urls[0]
    hp = serve_free_port(conf, port)
    if hp is None:
        return False, ("Tailscale Serve already uses HTTPS ports %s for other things, so TailWake didn't change "
                       "them. Free one of them (see `tailscale serve status`) and try again."
                       % ", ".join(map(str, SERVE_HTTPS_PORTS)))
    code, out = run_quiet([cli, "serve", "--bg", "--https=%d" % hp, "http://127.0.0.1:%d" % port], timeout=25)
    if code != 0:
        return False, _serve_failed(code, out)
    after = serve_urls(serve_config() or {}, port)
    message = "HTTPS address turned on: %s" % (after[0] if after else serve_url(tailscale_info()["dns"] or "?", hp))
    if hp != 443:
        message += "\n\nPort 443 already serves something else, so TailWake used port %d and left that alone." % hp
    return True, message


def serve_follow_port(old_port: int, new_port: int) -> str:
    """After a port change, point TailWake's Tailscale Serve handlers at the new port. Returns a message, or ''
    when Serve didn't point at TailWake."""
    cli = tailscale_cli()
    conf = serve_config() if cli and old_port != new_port else None
    mine = [h for h in serve_handlers(conf or {}) if h["local_port"] == old_port]
    if not mine:
        return ""
    for h in mine:
        flags = ["--https=%d" % h["https_port"], "--set-path", h["path"]]
        code, out = run_quiet([cli, "serve"] + flags + ["off"], timeout=25)
        if code == 0:
            code, out = run_quiet([cli, "serve", "--bg"] + flags + ["http://127.0.0.1:%d" % new_port], timeout=25)
        if code != 0:
            log.warning("Couldn't move the HTTPS address to port %d: %s", new_port, _serve_failed(code, out))
            return ("The HTTPS address still forwards to the old port %d and Tailscale didn't let TailWake change "
                    "it. Press \u201cTurn HTTPS address on\u201d in Settings \u2192 Tailscale.\n" % old_port)
    log.info("HTTPS address now forwards to port %d", new_port)
    return "The HTTPS address now forwards to the new port %d.\n" % new_port


_whois_cache = {}


def tailscale_whois(ip: str) -> bool:
    """True if `ip` is a device on this tailnet according to `tailscale whois` (cached for 5 minutes)."""
    hit = _whois_cache.get(ip)
    if hit and time.time() - hit[1] < 300:
        return hit[0]
    cli = tailscale_cli()
    ok = bool(cli) and run_quiet([cli, "whois", ip], timeout=5)[0] == 0
    _whois_cache[ip] = (ok, time.time())
    return ok


def parse_ip_addr(text: str) -> list:
    """`ip -o addr show` (Linux) -> ['192.168.1.5/24', ...]."""
    return re.findall(r"\binet6?\s+([0-9a-fA-F.:]+/\d+)", text)


def parse_ifconfig(text: str) -> list:
    """`ifconfig` (macOS/BSD) -> ['192.168.1.5/24', 'fe80::1/64', ...]."""
    out = []
    for m in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", text):
        mask = m.group(2)
        bits = bin(int(mask, 16)).count("1") if mask.startswith("0x") else \
            ipaddress.ip_network("0.0.0.0/" + mask).prefixlen
        out.append("%s/%d" % (m.group(1), bits))
    for m in re.finditer(r"\binet6\s+([0-9a-fA-F:]+)(?:%\S+)?\s+prefixlen\s+(\d+)", text):
        out.append("%s/%s" % (m.group(1), m.group(2)))
    return out


def parse_prefix_lines(text: str) -> list:
    """Lines of 'address/prefix' (Windows PowerShell) -> the same, without zone ids like %12."""
    out = []
    for line in text.splitlines():
        m = re.fullmatch(r"\s*([0-9a-fA-F.:]+)(?:%\S+)?/(\d+)\s*", line)
        if m:
            out.append("%s/%s" % (m.group(1), m.group(2)))
    return out


_networks = {"time": 0.0, "nets": []}


def local_networks(max_age: float = 60) -> list:
    """The networks this computer's own interfaces are on (no loopback, no single-address links such as
    Tailscale's own). Cached."""
    if time.time() - _networks["time"] < max_age:
        return _networks["nets"]
    if IS_WIN:
        rows = parse_prefix_lines(run_quiet(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetIPAddress | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }"], timeout=15)[1])
    elif IS_MAC or not sys.platform.startswith("linux"):
        rows = parse_ifconfig(run_quiet(["ifconfig"], timeout=5)[1])
    else:
        rows = parse_ip_addr(run_quiet(["ip", "-o", "addr", "show"], timeout=5)[1])
    own_ts = local_ip_toward("100.100.100.100")          # this computer's Tailscale address, if connected
    own_ts = ipaddress.ip_address(own_ts) if own_ts and in_tailscale_range(own_ts) else None
    nets = []
    for row in rows:
        try:
            n = ipaddress.ip_network(row, strict=False)
        except ValueError:
            continue
        if n.is_loopback or n.prefixlen >= n.max_prefixlen - 1 or n in nets or (own_ts and own_ts in n):
            continue
        nets.append(n)
    if not nets:                                   # couldn't list the interfaces: the /24 around the LAN address
        lan = local_ip_toward()
        if lan and not in_tailscale_range(lan):
            nets.append(subnet_24(lan))
    _networks.update(time=time.time(), nets=nets)
    return nets


def is_tailnet_address(a) -> bool:
    """Is this client address a Tailscale device? 100.64.0.0/10 is also used by some local networks (carrier-grade
    NAT): when this computer itself is on such a network, ask Tailscale to confirm."""
    if not in_tailscale_range(str(a)):
        return False
    if any(a in n for n in local_networks() if n.version == a.version and in_tailscale_range(str(n[0]))):
        return tailscale_whois(str(a))
    return True


def is_local_network_address(a) -> bool:
    return (a.is_private or a.is_link_local) and any(a in n for n in local_networks())


class LoginGuard:
    """Limits password guesses: `tries` attempts per address, then a lock-out that starts at `first_lock` seconds
    and doubles up to `max_lock`; plus at most `global_tries` attempts per minute from all addresses together.
    An attempt is counted before the password is checked, so parallel requests can't slip past the limit."""

    def __init__(self, tries=5, first_lock=60, max_lock=3600, global_tries=30):
        self.tries, self.first_lock, self.max_lock, self.global_tries = tries, first_lock, max_lock, global_tries
        self.lock = threading.Lock()
        self.by_client = {}
        self.recent = []
        self.global_logged = 0.0

    def attempt(self, client: str) -> int:
        """0 if this login attempt may go ahead, else the seconds to wait."""
        with self.lock:
            now = time.time()
            if len(self.by_client) > 2000:
                self.by_client = {k: e for k, e in self.by_client.items()
                                  if e["until"] > now or now - e["seen"] < 86400}
            e = self.by_client.setdefault(client, {"n": 0, "until": 0.0, "lock": 0, "seen": now})
            if now < e["until"]:
                return int(e["until"] - now) + 1
            self.recent = [t for t in self.recent if now - t < 60]
            if len(self.recent) >= self.global_tries:
                if now - self.global_logged > 60:
                    self.global_logged = now
                    log.warning("Too many login attempts overall: pausing logins for a minute")
                return int(60 - (now - self.recent[0])) + 1
            self.recent.append(now)
            e["n"] += 1
            e["seen"] = now
            if e["n"] >= self.tries:
                e["lock"] = min(self.max_lock, e["lock"] * 2 or self.first_lock)
                e["until"] = now + e["lock"]
                e["n"] = self.tries - 1          # after the lock-out: one more try, then a longer lock-out
                log.warning("Too many wrong passwords from %s: logins from there blocked for %d s", client, e["lock"])
            return 0

    def success(self, client: str) -> None:
        with self.lock:
            self.by_client.pop(client, None)


def page_urls(cfg: dict, ts: dict) -> list:
    urls = []
    if ts.get("dns"):
        urls.append("http://%s:%d/" % (ts["dns"], cfg["port"]))
    if ts.get("ip"):
        urls.append("http://%s:%d/" % (ts["ip"], cfg["port"]))
    return urls


# ---------------------------------------------------------------------------------------------------- web page

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#12695f"/>
<path d="M22.5 21.5a15 15 0 1 0 19 0" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round"/>
<path d="M32 13v19" stroke="#fff" stroke-width="5" stroke-linecap="round"/></svg>"""

MANIFEST = json.dumps({"name": APP, "short_name": APP, "start_url": "/", "display": "standalone",
                       "background_color": "#111718", "theme_color": "#12695f",
                       "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"}]})

PAGE_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="TailWake">
<meta name="format-detection" content="telephone=no">
<meta name="theme-color" content="#12695f">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.webmanifest">
<title>TailWake</title>
<style>
:root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --bg: #f5f7f8; --fg: #172026; --card: #ffffff; --line: #d8dee4; --soft: #eef3f4; --muted: #536166;
  --accent: #12695f; --accent-down: #0f5a52; --on: #1f8f5f; --off: #b42318; --wait: #b7791f; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #111718; --fg: #edf3f4; --card: #182123; --line: #2f3e41; --soft: #202b2e; --muted: #a7b3b6; }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; min-height: 100dvh; display: grid; place-items: start center;
  padding: max(18px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right)) max(18px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
  background: var(--bg); color: var(--fg); -webkit-text-size-adjust: 100%; }
main { width: min(100%, 520px); margin-top: 4vh; }
header { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
header img { width: 36px; height: 36px; }
h1 { margin: 0; font-size: 26px; }
.sub { color: var(--muted); font-size: 14px; margin: 2px 0 0; }
.card { padding: 18px; margin-bottom: 12px; border: 1px solid var(--line); border-radius: 10px; background: var(--card); }
.row { display: flex; align-items: center; gap: 12px; }
.dot { width: 14px; height: 14px; border-radius: 50%; flex: 0 0 auto; background: #8b949e; }
.online .dot { background: var(--on); box-shadow: 0 0 0 5px rgba(31, 143, 95, .16); }
.offline .dot { background: var(--off); box-shadow: 0 0 0 5px rgba(180, 35, 24, .14); }
.waking .dot { background: var(--wait); box-shadow: 0 0 0 5px rgba(183, 121, 31, .16); animation: pulse 1.2s infinite; }
@keyframes pulse { 50% { opacity: .35; } }
.name { font-size: 20px; font-weight: 800; overflow-wrap: anywhere; }
.state { font-size: 15px; font-weight: 700; }
.detail { margin: 10px 0 0; color: var(--muted); font-size: 14px; line-height: 1.45; overflow-wrap: anywhere; }
.meta { margin-top: 6px; color: var(--muted); font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
button { width: 100%; min-height: 52px; margin-top: 14px; padding: 14px 16px; border: 0; border-radius: 8px;
  background: var(--accent); color: #fff; font-size: 18px; font-weight: 800; cursor: pointer;
  touch-action: manipulation; -webkit-tap-highlight-color: transparent; }
button:active { transform: translateY(1px); background: var(--accent-down); }
button.secondary { background: var(--soft); color: var(--fg); min-height: 46px; font-size: 16px; }
button:disabled { opacity: .65; cursor: wait; }
input { width: 100%; min-height: 50px; margin-top: 10px; padding: 12px; font-size: 18px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--soft); color: var(--fg); }
.notice { padding: 12px; margin-bottom: 12px; border-left: 4px solid var(--accent); border-radius: 6px; background: var(--soft); }
.notice.bad { border-color: var(--off); }
.small { color: var(--muted); font-size: 13px; text-align: center; margin: 16px 0; }
.empty { color: var(--muted); }
</style>
</head>
"""

PAGE_BODY = """<body>
<main>
<header><img src="/icon.svg" alt=""><div><h1>TailWake</h1><p class="sub" id="server">&nbsp;</p></div></header>
<div id="notice"></div>
<div id="devices"><div class="card empty">Loading&hellip;</div></div>
<button type="button" class="secondary" id="refresh">Refresh status</button>
<p class="small">Status updates by itself while this page is open.</p>
</main>
<script>
(function () {
  var list = document.getElementById('devices');
  var noticeBox = document.getElementById('notice');
  var refreshButton = document.getElementById('refresh');
  var busy = {};
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function notice(text, bad) {
    noticeBox.textContent = '';
    if (!text) return;
    noticeBox.appendChild(el('div', 'notice' + (bad ? ' bad' : ''), text));
  }
  function render(data) {
    document.getElementById('server').textContent = 'via ' + data.server;
    list.textContent = '';
    if (!data.devices.length) {
      list.appendChild(el('div', 'card empty', 'No devices yet. Add one in TailWake\\u2019s settings on ' + data.server + '.'));
      return;
    }
    data.devices.forEach(function (d) {
      var card = el('section', 'card ' + d.state);
      var row = el('div', 'row');
      row.appendChild(el('span', 'dot'));
      var text = el('div');
      text.appendChild(el('div', 'name', d.name));
      text.appendChild(el('div', 'state', d.label));
      row.appendChild(text);
      card.appendChild(row);
      card.appendChild(el('p', 'detail', d.detail + (d.checked ? ' Checked at ' + d.checked + '.' : '')));
      card.appendChild(el('div', 'meta', d.mac + (d.ip ? '  \\u00b7  ' + d.ip : '')));
      var b = el('button', '', busy[d.id] ? 'Sending\\u2026' : (d.state === 'online' ? 'Wake again' : 'Wake ' + d.name));
      b.type = 'button';
      b.disabled = !!busy[d.id];
      b.addEventListener('click', function () { wake(d, b); });
      card.appendChild(b);
      list.appendChild(card);
    });
  }
  function load(fresh) {
    return fetch('/api/status' + (fresh ? '?fresh=1' : ''), { cache: 'no-store' })
      .then(function (r) { if (r.status === 401) { location.reload(); throw new Error('login'); } return r.json(); })
      .then(render)
      .catch(function (e) { if (e.message !== 'login') notice('Can\\u2019t reach TailWake. Is it still running?', true); });
  }
  function wake(d, b) {
    busy[d.id] = true; b.disabled = true; b.textContent = 'Sending\\u2026';
    fetch('/api/wake', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-TailWake': '1' },
                         body: JSON.stringify({ id: d.id }) })
      .then(function (r) { return r.json(); })
      .then(function (res) { notice(res.message, !res.ok); })
      .catch(function () { notice('The wake request failed. Is TailWake still running?', true); })
      .then(function () { busy[d.id] = false; load(false); });
  }
  refreshButton.addEventListener('click', function () {
    refreshButton.disabled = true; refreshButton.textContent = 'Checking\\u2026';
    load(true).then(function () { refreshButton.disabled = false; refreshButton.textContent = 'Refresh status'; });
  });
  setInterval(function () { if (!document.hidden) load(false); }, 4000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) load(false); });
  load(false);
}());
</script>
</body>
</html>
"""

LOGIN_BODY = """<body>
<main>
<header><img src="/icon.svg" alt=""><div><h1>TailWake</h1><p class="sub">Password needed</p></div></header>
%s
<form class="card" method="post" action="/login">
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" autofocus>
<button type="submit">Open</button>
</form>
</main>
</body>
</html>
"""

DENIED_PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TailWake</title><body style="font-family:system-ui,sans-serif;max-width:520px;margin:10vh auto;padding:0 16px">
<h1>Not allowed</h1><p>%s</p>
<p>Your address: %s</p></body>"""


class QuickServer(ThreadingHTTPServer):
    """ThreadingHTTPServer without the reverse-DNS lookup in server_bind (socket.getfqdn can hang on macOS)."""
    daemon_threads = True
    request_queue_size = 64                   # a phone opens several connections at once
    allow_reuse_address = not IS_WIN          # on Windows this would let two programs share the port

    def server_bind(self):
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class WebHandler(BaseHTTPRequestHandler):
    server_version = "TailWake/" + VERSION
    app = None          # set by App

    def log_message(self, fmt, *args):
        log.debug("web %s - %s", self.client_address[0], fmt % args)

    # -- helpers
    def _send(self, code: int, body, ctype: str = "text/html; charset=utf-8", headers: dict = None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8")

    def _client(self):
        try:
            a = ipaddress.ip_address(self.client_address[0].split("%")[0])
        except ValueError:
            return None
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        return a

    def _allowed(self) -> bool:
        a = self._client()
        if a is None:
            return False
        if a.is_loopback or is_tailnet_address(a):
            return True
        cfg = self.app.cfg
        return cfg["access"] == "network" and bool(cfg.get("password_hash")) and is_local_network_address(a)

    def _denied_reason(self) -> str:
        cfg = self.app.cfg
        if cfg["access"] != "network":
            return "This TailWake only answers devices on your Tailscale network."
        if not cfg.get("password_hash"):
            return ("This TailWake only answers devices on your Tailscale network. Local network access is switched "
                    "on but needs a password: set one in TailWake's settings.")
        return "This TailWake only answers devices on your Tailscale network and its own local network."

    def _host_ok(self) -> bool:
        """Only answer requests addressed to this computer (stops DNS rebinding from other websites)."""
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        if host.startswith("["):
            name = host[1:host.find("]")] if "]" in host else host
        else:
            name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        name = name.rstrip(".")
        if name == "localhost":
            return True
        try:
            ipaddress.ip_address(name.split("%")[0])
            return True
        except ValueError:
            pass
        return name in self.app.host_names()

    def _check_request(self) -> bool:
        """Host and client address checks for every request. Sends the refusal and returns False if not allowed."""
        if not self._host_ok():
            log.info("Refused a request from %s for host %r", self.client_address[0], self.headers.get("Host"))
            self._send(421, "This TailWake doesn't answer to that host name.", "text/plain; charset=utf-8")
            return False
        if not self._allowed():
            if self.command == "POST":
                self._send(403, "Not allowed", "text/plain; charset=utf-8")
            else:
                self._send(403, DENIED_PAGE % (self._denied_reason(), self.client_address[0]))
            return False
        return True

    def _login_key(self) -> str:
        """Who is guessing: the client address, or the original one when Tailscale Serve proxies from loopback."""
        a = self._client()
        forwarded = (self.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
        if a is not None and a.is_loopback and forwarded:
            return forwarded
        return self.client_address[0]

    def _cookie_value(self) -> str:
        cfg = self.app.cfg
        return hmac.new(cfg["secret"].encode(), cfg["password_hash"].encode(), hashlib.sha256).hexdigest()

    def _authed(self) -> bool:
        if not self.app.cfg.get("password_hash"):
            return True
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "tailwake" and hmac.compare_digest(v, self._cookie_value()):
                return True
        return False

    def _body(self, limit: int = 4096) -> bytes:
        try:
            n = min(int(self.headers.get("Content-Length") or 0), limit)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    # -- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._check_request():
            return None
        path = urllib.parse.urlsplit(self.path).path
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if path == "/icon.svg":
            return self._send(200, ICON_SVG, "image/svg+xml")
        if path == "/manifest.webmanifest":
            return self._send(200, MANIFEST, "application/manifest+json")
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if path == "/":
            if not self._authed():
                return self._send(200, PAGE_HEAD + LOGIN_BODY % "")
            return self._send(200, PAGE_HEAD + PAGE_BODY)
        if path == "/api/status":
            if not self._authed():
                return self._json(401, {"error": "login needed"})
            return self._json(200, self.app.web_status(fresh="fresh" in query))
        self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if not self._check_request():
            return None
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            form = urllib.parse.parse_qs(self._body().decode("utf-8", "replace"))
            who = self._login_key()
            wait = self.app.logins.attempt(who)
            if wait:
                notice = '<div class="notice bad">Too many wrong passwords. Try again in %s.</div>' % (
                    "%d minutes" % ((wait + 59) // 60) if wait > 90 else "%d seconds" % wait)
                return self._send(429, PAGE_HEAD + LOGIN_BODY % notice, headers={"Retry-After": str(wait)})
            if check_password(self.app.cfg, (form.get("password") or [""])[0]):
                self.app.logins.success(who)
                cookie = "tailwake=%s; Path=/; Max-Age=31536000; HttpOnly; SameSite=Strict" % self._cookie_value()
                return self._send(303, "", headers={"Location": "/", "Set-Cookie": cookie})
            time.sleep(1.0)
            log.info("Wrong password from %s", who)
            return self._send(401, PAGE_HEAD + LOGIN_BODY % '<div class="notice bad">Wrong password.</div>')
        if path == "/api/wake":
            if not self._authed():
                return self._json(401, {"ok": False, "message": "Log in first."})
            if self.headers.get("X-TailWake") != "1":
                return self._json(400, {"ok": False, "message": "Bad request."})
            try:
                key = json.loads(self._body() or b"{}").get("id", "")
            except ValueError:
                key = ""
            ok, message = self.app.wake(key, source=self.client_address[0])
            return self._json(200 if ok else 400, {"ok": ok, "message": message})
        self._send(404, "Not found", "text/plain; charset=utf-8")


class ControlHandler(BaseHTTPRequestHandler):
    """Local control channel used by `tailwake stop/status/...` and the settings window. 127.0.0.1 + token only."""
    app = None

    def log_message(self, fmt, *args):
        pass

    def _reply(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.client_address[0] != "127.0.0.1" or not hmac.compare_digest(
                self.headers.get("X-TailWake-Token") or "", self.app.token):
            return self._reply({"error": "forbidden"}, 403)
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
            arg = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            arg = {}
        cmd = self.path.strip("/")
        app = self.app
        if cmd == "status":
            return self._reply(app.status_summary())
        if cmd == "stop":
            self._reply({"ok": True})
            threading.Thread(target=app.quit, daemon=True).start()
            return None
        if cmd == "reload":
            app.reload()
            return self._reply(app.status_summary())
        if cmd == "pause":
            app.stop_server()
            return self._reply(app.status_summary())
        if cmd in ("resume", "restart"):
            app.stop_server()
            app.start_server()
            return self._reply(app.status_summary())
        if cmd == "wake":
            ok, message = app.wake(arg.get("id", ""), source="command line")
            return self._reply({"ok": ok, "message": message})
        if cmd == "check":
            app.check_all()
            return self._reply(app.status_summary())
        self._reply({"error": "unknown command"}, 404)


# --------------------------------------------------------------------------------------------------------- the app

class App:
    def __init__(self):
        self.cfg = load_config()
        self.lock = threading.RLock()
        self.status = {}                 # device id -> check result
        self.woken = {}                  # device id -> time a wake packet was sent
        self.last_view = 0.0
        self.server = None
        self.server_error = ""
        self.control = None
        self.token = secrets.token_hex(16)
        self.quit_event = threading.Event()
        self.check_event = threading.Event()
        self.check_lock = threading.Lock()
        self.tray = None
        self._ts = {}
        self._ts_time = 0.0
        self.logins = LoginGuard()

    # -- tailscale (cached)
    def tailscale(self, max_age: float = 30) -> dict:
        if time.time() - self._ts_time > max_age:
            self._ts = tailscale_info()
            self._ts_time = time.time()
        return self._ts

    def host_names(self) -> set:
        """Host names this computer answers to: its own name and its Tailscale (MagicDNS) name."""
        short = socket.gethostname().lower().rstrip(".")
        names = {short, short.split(".")[0], short.split(".")[0] + ".local"}
        dns = (self.tailscale().get("dns") or "").lower()
        if dns:
            names.update((dns, dns.split(".")[0]))
        return names

    def url(self) -> str:
        urls = page_urls(self.cfg, self.tailscale())
        return urls[0] if urls else "http://127.0.0.1:%d/" % self.cfg["port"]

    # -- web server
    def start_server(self) -> bool:
        with self.lock:
            if self.server:
                return True
            WebHandler.app = self
            try:
                srv = QuickServer(("0.0.0.0", self.cfg["port"]), WebHandler)
            except OSError as e:
                self.server_error = "Port %d can't be used (%s). Pick another port in Settings." % (
                    self.cfg["port"], e.strerror or e)
                log.error(self.server_error)
                self.refresh_tray()
                return False
            self.server = srv
            self.server_error = ""
            threading.Thread(target=srv.serve_forever, name="web", daemon=True).start()
        log.info("Web page running on port %d: %s", self.cfg["port"], self.url())
        self.refresh_tray()
        return True

    def stop_server(self) -> None:
        with self.lock:
            srv, self.server = self.server, None
        if srv:
            srv.shutdown()
            srv.server_close()
            log.info("Web page stopped")
        self.refresh_tray()

    def toggle_server(self) -> None:
        if self.server:
            self.stop_server()
        else:
            self.start_server()

    def start_control(self) -> None:
        ControlHandler.app = self
        self.control = QuickServer(("127.0.0.1", 0), ControlHandler)
        threading.Thread(target=self.control.serve_forever, name="control", daemon=True).start()
        write_json(state_path(), {"pid": os.getpid(), "control_port": self.control.server_address[1],
                                  "token": self.token, "version": VERSION})
        if not IS_WIN:
            try:
                os.chmod(state_path(), 0o600)
            except OSError:
                pass

    def reload(self) -> None:
        old_port = self.cfg["port"]
        self.cfg = load_config()
        with self.lock:
            ids = {d["id"] for d in self.cfg["devices"]}
            self.status = {k: v for k, v in self.status.items() if k in ids}
        log.info("Settings reloaded")
        if self.cfg["port"] != old_port:
            threading.Thread(target=serve_follow_port, args=(old_port, self.cfg["port"]), daemon=True).start()
            if self.server:
                self.stop_server()
                self.start_server()
        elif not self.server and self.server_error:
            self.start_server()
        self.check_event.set()
        self.refresh_tray()

    # -- status
    def device_state(self, d: dict) -> dict:
        st = self.status.get(d["id"])
        woke = self.woken.get(d["id"], 0)
        waking = time.time() - woke < WAKE_WATCH_SECONDS
        if st is None:
            state, label, detail = ("waking", "Waking\u2026", "Wake packet sent. Waiting for it to come online.") \
                if waking else ("unknown", "Checking\u2026", "Checking status\u2026")
        elif st["online"]:
            state, label, detail = "online", "Online", st["detail"]
        elif waking:
            state, label = "waking", "Waking\u2026"
            detail = "Wake packet sent %d s ago. Waiting for it to come online." % (time.time() - woke)
        else:
            state, label, detail = "offline", "Offline", st["detail"]
        return {"id": d["id"], "name": d["name"], "mac": d["mac"].upper(), "ip": (st or {}).get("seen_ip") or d["ip"],
                "state": state, "label": label, "detail": detail, "checked": (st or {}).get("checked", "")}

    def web_status(self, fresh: bool = False) -> dict:
        self.last_view = time.time()
        if fresh:
            self.check_all()
        else:
            self.check_event.set()
        return {"server": socket.gethostname(), "devices": [self.device_state(d) for d in self.cfg["devices"]]}

    def status_summary(self) -> dict:
        ts = self.tailscale()
        return {"running": True, "pid": os.getpid(), "version": VERSION, "serving": bool(self.server),
                "error": self.server_error, "port": self.cfg["port"], "urls": page_urls(self.cfg, ts),
                "tailscale": ts, "devices": [self.device_state(d) for d in self.cfg["devices"]]}

    def check_all(self) -> None:
        with self.check_lock:
            devices = list(self.cfg["devices"])
            results = {}

            def one(d):
                try:
                    results[d["id"]] = check_device(d)
                except Exception as e:                          # never let a check kill the app
                    log.exception("status check failed for %s", d["name"])
                    results[d["id"]] = {"online": False, "seen_ip": "", "checked": time.strftime("%H:%M:%S"),
                                        "detail": "Status check failed: %s" % e}
                results[d["id"]]["_t"] = time.time()

            threads = [threading.Thread(target=one, args=(d,), daemon=True) for d in devices]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            came_up = []
            with self.lock:
                for d in devices:
                    r = results.get(d["id"])
                    if not r:
                        continue
                    before = self.status.get(d["id"])
                    if r["online"] and time.time() - self.woken.get(d["id"], 0) < WAKE_WATCH_SECONDS \
                            and not (before and before["online"]):
                        came_up.append(d["name"])
                        self.woken.pop(d["id"], None)
                    self.status[d["id"]] = r
        for name in came_up:
            log.info("%s is online", name)
            self.notify("%s is online." % name)
        self.refresh_tray()

    def checker(self) -> None:
        """Checks status while someone is looking (page open, after a wake) or always if background checks are on."""
        if self.cfg["devices"]:
            self.check_all()
        while not self.quit_event.is_set():
            self.check_event.wait(timeout=1.0)
            self.check_event.clear()
            if self.quit_event.is_set():
                break
            watching = time.time() - self.last_view < VIEW_WINDOW_SECONDS
            waking = any(time.time() - t < WAKE_WATCH_SECONDS for t in self.woken.values())
            period = 4 if waking else self.cfg["check_seconds"]
            if (watching or waking or self.cfg["background_checks"]) and self.needs_check_within(period):
                self.check_all()

    def needs_check_within(self, period: float) -> bool:
        if not self.cfg["devices"]:
            return False
        newest = max((s.get("_t", 0) for s in self.status.values()), default=0)
        return time.time() - newest >= period

    # -- actions
    def wake(self, key: str, source: str = "") -> tuple:
        d = find_device(self.cfg, key)
        if not d:
            return False, "Unknown device."
        try:
            message = send_wake(d)
        except OSError as e:
            log.error("Wake for %s failed: %s", d["name"], e)
            return False, "Couldn't send the wake packet: %s" % e
        if source:
            log.info("Wake for %s requested by %s", d["name"], source)
        with self.lock:
            self.woken[d["id"]] = time.time()
            if self.status.get(d["id"], {}).get("online"):
                self.woken.pop(d["id"], None)
        self.check_event.set()
        self.refresh_tray()
        return True, message + " It usually takes 10\u201360 seconds to come online."

    def notify(self, text: str) -> None:
        if not self.cfg.get("notifications") or not self.tray:
            return
        try:
            if getattr(self.tray, "HAS_NOTIFICATION", False):
                self.tray.notify(text, APP)
        except Exception:
            log.debug("notification failed", exc_info=True)

    def refresh_tray(self) -> None:
        if self.tray:
            try:
                self.tray.refresh()
            except Exception:
                log.debug("tray refresh failed", exc_info=True)

    def quit(self) -> None:
        if self.quit_event.is_set():
            return
        log.info("Quitting")
        self.quit_event.set()
        self.check_event.set()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass

    # -- main loop
    def run(self, tray: bool = True) -> int:
        self.start_control()
        self.start_server()
        threading.Thread(target=self.checker, name="checker", daemon=True).start()
        threading.Thread(target=self.tailscale, kwargs={"max_age": 0}, daemon=True).start()
        threading.Thread(target=local_networks, daemon=True).start()
        if self.cfg["access"] == "network" and not self.cfg["password_hash"]:
            log.warning("Local network access is on but no password is set, so only Tailscale devices can open the "
                        "page. Set a password in Settings or with `tailwake config --password`.")
        for d in self.cfg["_invalid_devices"]:
            log.warning("A device in %s has an unreadable MAC address and is skipped until it is fixed: %s",
                        config_path(), (d.get("name") if isinstance(d, dict) else None) or repr(d)[:60])
        if not IS_WIN:
            import signal
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                try:
                    signal.signal(sig, lambda *_: self.quit())
                except (ValueError, OSError):
                    pass
        try:
            started = False
            if tray:
                self.tray = Tray.create(self)
                if self.tray:
                    started = True
                    self.tray.run()          # blocks on the main thread until Quit
            if not started:
                log.info("Running without a tray icon. Use `tailwake settings` / `tailwake stop`.")
                while not self.quit_event.wait(1.0):
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self.quit_event.set()
            self.stop_server()
            if self.control:
                self.control.shutdown()
            state = read_json(state_path(), {})
            if isinstance(state, dict) and state.get("pid") == os.getpid():
                try:
                    os.remove(state_path())
                except OSError:
                    pass
        return 0


# ---------------------------------------------------------------------------------------------------------- tray

def tray_image(color: tuple):
    from PIL import Image, ImageDraw
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, size - 3, size - 3), fill=color)
    d.arc((16, 17, 48, 49), start=-50, end=230, fill=(255, 255, 255), width=6)
    d.line((32, 11, 32, 31), fill=(255, 255, 255), width=6)
    return img


class Tray:
    GREEN, GREY, AMBER = (31, 143, 95), (96, 106, 116), (190, 125, 20)

    def __init__(self, app: App, pystray):
        self.app = app
        self.pystray = pystray
        self.color = None
        self.icon = pystray.Icon("tailwake", tray_image(self.GREY), APP, menu=pystray.Menu(self.items))
        self.HAS_NOTIFICATION = getattr(self.icon, "HAS_NOTIFICATION", False)

    @staticmethod
    def create(app: App):
        if not IS_WIN and not IS_MAC and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            log.info("No desktop session found")
            return None
        try:
            import pystray
            from PIL import Image  # noqa: F401
        except Exception as e:
            log.warning("Tray icon unavailable (%s). Install it with: %s -m pip install pystray Pillow",
                        e, sys.executable)
            return None
        try:
            return Tray(app, pystray)
        except Exception as e:
            log.warning("Tray icon unavailable: %s", e)
            return None

    def items(self):
        p, app = self.pystray, self.app
        Item = p.MenuItem
        if app.server:
            head = "TailWake \u2013 " + app.url()
        else:
            head = "TailWake \u2013 " + (app.server_error or "web page stopped")
        yield Item(head, None, enabled=False)
        yield p.Menu.SEPARATOR
        if not app.cfg["devices"]:
            yield Item("No devices yet: open Settings", self.on_settings)
        for d in app.cfg["devices"]:
            st = app.device_state(d)
            yield Item("Wake %s  (%s)" % (d["name"], st["label"].lower()), self.wake_action(d["id"]))
        yield Item("Check status now", self.on_check)
        yield p.Menu.SEPARATOR
        yield Item("Open web page", self.on_open, default=True)
        yield Item("Copy web address", self.on_copy)
        yield Item("Settings\u2026", self.on_settings)
        yield p.Menu.SEPARATOR
        yield Item("Web page on", self.on_toggle, checked=lambda item: bool(self.app.server))
        yield Item("Start at login", self.on_autostart, checked=lambda item: autostart_enabled())
        yield Item("Quit TailWake", self.on_quit)

    def wake_action(self, device_id):
        def action(icon, item):
            threading.Thread(target=self._wake, args=(device_id,), daemon=True).start()
        return action

    def _wake(self, device_id):
        ok, message = self.app.wake(device_id, source="tray")
        self.app.notify(message if ok else "Wake failed: " + message)

    def on_check(self, icon, item):
        threading.Thread(target=self.app.check_all, daemon=True).start()

    def on_open(self, icon, item):
        webbrowser.open(self.app.url())

    def on_copy(self, icon, item):
        copy_to_clipboard(self.app.url())
        self.app.notify("Copied " + self.app.url())

    def on_settings(self, icon, item):
        open_settings_window()

    def on_toggle(self, icon, item):
        threading.Thread(target=self.app.toggle_server, daemon=True).start()

    def on_autostart(self, icon, item):
        try:
            if autostart_enabled():
                autostart_off()
            else:
                autostart_on()
        except Exception as e:
            log.error("Start at login: %s", e)
            self.app.notify("Start at login failed: %s" % e)
        self.refresh()

    def on_quit(self, icon, item):
        self.app.quit()

    def refresh(self):
        app = self.app
        if not app.server:
            color = self.AMBER
        elif any(s.get("online") for s in app.status.values()):
            color = self.GREEN
        else:
            color = self.GREY
        if color != self.color:
            self.color = color
            self.icon.icon = tray_image(color)
        online = [d["name"] for d in app.cfg["devices"] if app.status.get(d["id"], {}).get("online")]
        self.icon.title = APP + (" \u2013 online: " + ", ".join(online) if online else "")
        self.icon.update_menu()

    def notify(self, text, title=APP):
        self.icon.notify(text, title)

    def stop(self):
        self.icon.stop()

    def run(self):
        if IS_MAC:
            try:                                          # menu-bar only: no Dock icon
                from AppKit import NSApplication
                NSApplication.sharedApplication().setActivationPolicy_(1)
            except Exception:
                pass

        def setup(icon):
            icon.visible = True
            self.refresh()

        self.icon.run(setup=setup)


def copy_to_clipboard(text: str) -> bool:
    if IS_WIN:
        cmds = [["clip"]]
    elif IS_MAC:
        cmds = [["pbcopy"]]
    else:
        cmds = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for cmd in cmds:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-16le" if IS_WIN else "utf-8"), timeout=3,
                               creationflags=NO_WINDOW)
                return True
            except (OSError, subprocess.SubprocessError):
                continue
    try:                                    # last resort: tkinter
        import tkinter
        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.after(500, r.destroy)
        r.mainloop()
        return True
    except Exception:
        return False


def open_settings_window() -> None:
    subprocess.Popen([gui_python(), script_path(), "settings"], creationflags=NO_WINDOW,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     close_fds=True)


def open_path(path: str) -> None:
    if IS_WIN:
        os.startfile(path)  # noqa: S606
    elif IS_MAC:
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ----------------------------------------------------------------------------------------------- start at login

AUTOSTART_ID = "io.github.tailwake"


def autostart_command() -> list:
    return [gui_python(), script_path(), "run"]


def _linux_desktop_file() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "autostart",
                        "tailwake.desktop")


def _linux_unit_file() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "systemd", "user",
                        "tailwake.service")


def _mac_plist() -> str:
    return os.path.expanduser("~/Library/LaunchAgents/%s.plist" % AUTOSTART_ID)


def autostart_enabled() -> bool:
    if IS_WIN:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                winreg.QueryValueEx(k, APP)
                return True
        except OSError:
            return False
    if IS_MAC:
        return os.path.exists(_mac_plist())
    if os.path.exists(_linux_desktop_file()):
        return True
    if os.path.exists(_linux_unit_file()):
        code, out = run_quiet(["systemctl", "--user", "is-enabled", "tailwake.service"], timeout=5)
        return out.strip() == "enabled"
    return False


def _desktop_quote(arg: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:+-]+", arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'


def autostart_on(service: bool = False) -> str:
    cmd = autostart_command()
    if IS_WIN:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, APP, 0, winreg.REG_SZ, subprocess.list2cmdline(cmd))
        return "TailWake will start when you sign in to Windows."
    if IS_MAC:
        import plistlib
        os.makedirs(os.path.dirname(_mac_plist()), exist_ok=True)
        with open(_mac_plist(), "wb") as f:
            plistlib.dump({"Label": AUTOSTART_ID, "ProgramArguments": cmd, "RunAtLoad": True,
                           "ProcessType": "Interactive", "LimitLoadToSessionType": "Aqua"}, f)
        return "TailWake will start when you log in to macOS."
    desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if desktop and not service:
        path = _linux_desktop_file()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("[Desktop Entry]\nType=Application\nName=TailWake\nComment=Wake your computers over Tailscale\n"
                    "Exec=%s\nIcon=system-shutdown\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
                    % " ".join(_desktop_quote(a) for a in cmd))
        return "TailWake will start when you log in to your desktop."
    path = _linux_unit_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("[Unit]\nDescription=TailWake (Wake-on-LAN over Tailscale)\nAfter=network-online.target\n"
                "Wants=network-online.target\n\n[Service]\nExecStart=%s\nRestart=on-failure\nRestartSec=5\n\n"
                "[Install]\nWantedBy=default.target\n" % " ".join(_desktop_quote(a) for a in cmd))
    run_quiet(["systemctl", "--user", "daemon-reload"], timeout=10)
    code, out = run_quiet(["systemctl", "--user", "enable", "tailwake.service"], timeout=10)
    if code != 0:
        raise OSError("systemctl --user enable failed: " + out.strip())
    return ("TailWake will start as a systemd user service. To start it at boot without logging in, run once:\n"
            "  sudo loginctl enable-linger $USER")


def autostart_off() -> str:
    if IS_WIN:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, APP)
        except OSError:
            pass
    elif IS_MAC:
        if os.path.exists(_mac_plist()):
            os.remove(_mac_plist())
    else:
        if os.path.exists(_linux_desktop_file()):
            os.remove(_linux_desktop_file())
        if os.path.exists(_linux_unit_file()):
            run_quiet(["systemctl", "--user", "disable", "tailwake.service"], timeout=10)
            os.remove(_linux_unit_file())
            run_quiet(["systemctl", "--user", "daemon-reload"], timeout=10)
    return "TailWake will no longer start at login."


# ------------------------------------------------------------------------------------------- control (client side)

def control(cmd: str, arg: dict = None, timeout: float = 5.0):
    """Send a command to the running TailWake. Returns its reply (dict) or None if it isn't running."""
    state = read_json(state_path(), None)
    if not isinstance(state, dict) or not state.get("control_port"):
        return None
    req = urllib.request.Request("http://127.0.0.1:%d/%s" % (state["control_port"], cmd),
                                 data=json.dumps(arg or {}).encode(), method="POST",
                                 headers={"X-TailWake-Token": state.get("token", ""),
                                          "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def start_background() -> dict:
    """Start `tailwake run` detached. Returns its status (or None if it didn't come up)."""
    status = control("status")
    if status:
        return status
    cmd = autostart_command()
    os.makedirs(config_dir(), exist_ok=True)
    if IS_WIN:
        flags = 0x00000008 | 0x00000200 | NO_WINDOW      # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | NO_WINDOW
        subprocess.Popen(cmd, creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(cmd, start_new_session=True, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        time.sleep(0.2)
        status = control("status")
        if status:
            return status
    return None


# ------------------------------------------------------------------------------------------------ settings window

def settings_window(start_tab: str = "") -> int:
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("The settings window needs tkinter, which this Python doesn't have.\n"
              "Use the command line instead (see `tailwake help`), or install tkinter for your Python.")
        return 1

    cfg = load_config()
    root = tk.Tk()
    root.title("TailWake settings")
    root.minsize(560, 430)
    try:
        root.iconphoto(True, tk.PhotoImage(data=base64.b64encode(_tk_icon_png()).decode()))
    except Exception:
        pass
    pad = {"padx": 10, "pady": 6}
    work = queue.Queue()

    def in_background(fn, done):
        """Run fn() off the UI thread; call done(result) back on it."""
        def worker():
            try:
                work.put((done, fn()))
            except Exception as e:                              # pass the error to the callback
                work.put((done, e))
        threading.Thread(target=worker, daemon=True).start()

    def pump():
        try:
            while True:
                done, result = work.get_nowait()
                done(result)
        except queue.Empty:
            pass
        root.after(100, pump)

    root.after(100, pump)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))

    # ---- Devices
    tab = ttk.Frame(nb)
    nb.add(tab, text="Devices")
    ttk.Label(tab, text="Computers TailWake can wake. They must be on the same local network as this computer.",
              wraplength=520).pack(anchor="w", **pad)
    tree = ttk.Treeview(tab, columns=("name", "mac", "ip"), show="headings", height=8)
    for col, title, width in (("name", "Name", 180), ("mac", "MAC address", 160), ("ip", "IP address", 140)):
        tree.heading(col, text=title)
        tree.column(col, width=width)
    tree.pack(fill="both", expand=True, padx=10)
    if cfg["_invalid_devices"]:
        ttk.Label(tab, foreground="#b42318", wraplength=520, text=(
            "%d device(s) in the settings file have a MAC address TailWake can't read and are skipped. They are kept "
            "in the file: fix them there (App tab \u2192 Open settings folder) or add them again here."
            % len(cfg["_invalid_devices"]))).pack(anchor="w", padx=10, pady=(4, 0))

    def refresh_tree():
        tree.delete(*tree.get_children())
        for d in cfg["devices"]:
            tree.insert("", "end", iid=d["id"], values=(d["name"], d["mac"].upper(), d["ip"] or "\u2013"))

    def selected():
        sel = tree.selection()
        return next((d for d in cfg["devices"] if sel and d["id"] == sel[0]), None)

    def edit_device(device=None, prefill=None):
        win = tk.Toplevel(root)
        win.title("Edit device" if device else "Add device")
        win.transient(root)
        win.resizable(False, False)
        src = dict(device or {})
        src.update(prefill or {})
        fields = {}
        rows = (("name", "Name", "A name you'll recognise, e.g. Desktop PC"),
                ("mac", "MAC address", "Its wired network adapter, e.g. 00:1A:2B:3C:4D:5E"),
                ("ip", "IP address", "Recommended: lets TailWake show online/offline"),
                ("broadcast", "Broadcast address", "Optional. Only if waking doesn't work, e.g. 192.168.1.255"))
        for r, (key, label, hint) in enumerate(rows):
            ttk.Label(win, text=label).grid(row=r * 2, column=0, sticky="w", padx=10, pady=(8, 0))
            var = tk.StringVar(value=src.get(key, "").upper() if key == "mac" else src.get(key, ""))
            ttk.Entry(win, textvariable=var, width=34).grid(row=r * 2, column=1, sticky="we", padx=10, pady=(8, 0))
            ttk.Label(win, text=hint, foreground="#666").grid(row=r * 2 + 1, column=1, sticky="w", padx=10)
            fields[key] = var

        def look_up():
            ip = fields["ip"].get().strip()
            if not is_ipv4(ip):
                messagebox.showinfo("Look up MAC", "Type the device's IP address first (the device must be on).",
                                    parent=win)
                return
            lookup_btn.config(state="disabled", text="Looking\u2026")

            def done(mac):
                lookup_btn.config(state="normal", text="Look up MAC from IP")
                if isinstance(mac, str) and mac:
                    fields["mac"].set(mac.upper())
                else:
                    messagebox.showinfo("Look up MAC", "No answer from %s. Is the device on and on this network?"
                                        % ip, parent=win)
            in_background(lambda: mac_for_ip(ip), done)

        lookup_btn = ttk.Button(win, text="Look up MAC from IP", command=look_up)
        lookup_btn.grid(row=8, column=1, sticky="w", padx=10, pady=8)

        def ok():
            name = fields["name"].get().strip()
            mac = normalize_mac(fields["mac"].get())
            ip = fields["ip"].get().strip()
            bc = fields["broadcast"].get().strip()
            if not name:
                return messagebox.showerror("Device", "Give the device a name.", parent=win)
            if not mac:
                return messagebox.showerror("Device", "That MAC address doesn't look right.\n"
                                            "It has six pairs, e.g. 00:1A:2B:3C:4D:5E.", parent=win)
            if ip and not is_ipv4(ip):
                return messagebox.showerror("Device", "The IP address should look like 192.168.1.20.", parent=win)
            if bc and not is_ipv4(bc):
                return messagebox.showerror("Device", "The broadcast address should look like 192.168.1.255.",
                                            parent=win)
            if any(d["name"].lower() == name.lower() and d is not device for d in cfg["devices"]):
                return messagebox.showerror("Device", "Another device already has that name.", parent=win)
            if device:
                device.update(name=name, mac=mac, ip=ip, broadcast=bc)
            else:
                cfg["devices"].append({"id": secrets.token_hex(4), "name": name, "mac": mac, "ip": ip,
                                       "broadcast": bc})
            refresh_tree()
            mark_dirty()
            win.destroy()

        bar = ttk.Frame(win)
        bar.grid(row=9, column=0, columnspan=2, sticky="e", padx=10, pady=10)
        ttk.Button(bar, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(bar, text="OK", command=ok).pack(side="right", padx=6)
        win.bind("<Return>", lambda e: ok())
        win.grab_set()

    def remove_device():
        d = selected()
        if d and messagebox.askyesno("Remove", "Remove %s?" % d["name"], parent=root):
            cfg["devices"].remove(d)
            refresh_tree()
            mark_dirty()

    def find_devices():
        win = tk.Toplevel(root)
        win.title("Devices on this network")
        win.transient(root)
        msg = ttk.Label(win, text="Looking for devices on your network\u2026 (only devices that are on show up)")
        msg.pack(anchor="w", padx=10, pady=8)
        ft = ttk.Treeview(win, columns=("ip", "mac", "name"), show="headings", height=14)
        for col, title, width in (("ip", "IP address", 130), ("mac", "MAC address", 150), ("name", "Name", 240)):
            ft.heading(col, text=title)
            ft.column(col, width=width)
        ft.pack(fill="both", expand=True, padx=10)

        def use():
            sel = ft.selection()
            if not sel:
                return
            ip, mac, name = ft.item(sel[0], "values")
            win.destroy()
            short = name.split(".")[0] if name else ""
            edit_device(prefill={"ip": ip, "mac": mac, "name": short})

        def done(rows):
            if isinstance(rows, Exception):
                msg.config(text="The search failed: %s" % rows)
                return
            for ip, mac, name, _ in rows:
                ft.insert("", "end", values=(ip, mac.upper(), name))
            msg.config(text="Found %d. Pick one and press Use, or double-click it." % len(rows) if rows
                       else "Nothing found. Is this computer on the same network as the device?")

        ft.bind("<Double-1>", lambda e: use())
        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=10, pady=10)
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        ttk.Button(bar, text="Use", command=use).pack(side="right", padx=6)
        in_background(scan_network, done)

    def wake_now():
        d = selected()
        if not d:
            return messagebox.showinfo("Wake", "Pick a device first.", parent=root)
        reply = control("wake", {"id": d["id"]})
        if reply is None:
            try:
                message = send_wake(d)
            except OSError as e:
                message = "Couldn't send the wake packet: %s" % e
        else:
            message = reply.get("message", "")
        messagebox.showinfo("Wake", message, parent=root)

    bar = ttk.Frame(tab)
    bar.pack(fill="x", padx=10, pady=8)
    ttk.Button(bar, text="Find on network\u2026", command=find_devices).pack(side="left")
    ttk.Button(bar, text="Add\u2026", command=lambda: edit_device()).pack(side="left", padx=6)
    ttk.Button(bar, text="Edit\u2026", command=lambda: selected() and edit_device(selected())).pack(side="left")
    ttk.Button(bar, text="Remove", command=remove_device).pack(side="left", padx=6)
    ttk.Button(bar, text="Wake now", command=wake_now).pack(side="right")
    tree.bind("<Double-1>", lambda e: selected() and edit_device(selected()))
    refresh_tree()

    # ---- Web page
    tab = ttk.Frame(nb)
    nb.add(tab, text="Web page")
    port_var = tk.StringVar(value=str(cfg["port"]))
    access_var = tk.StringVar(value=cfg["access"])
    pw_var = tk.StringVar()
    clear_pw = tk.BooleanVar(value=False)
    bg_var = tk.BooleanVar(value=cfg["background_checks"])
    notify_var = tk.BooleanVar(value=cfg["notifications"])
    f = ttk.Frame(tab)
    f.pack(fill="x", **pad)
    ttk.Label(f, text="Port").grid(row=0, column=0, sticky="w")
    ttk.Spinbox(f, from_=1024, to=65535, textvariable=port_var, width=8).grid(row=0, column=1, sticky="w", padx=8)
    ttk.Label(f, text="Who can open the page").grid(row=1, column=0, sticky="nw", pady=(12, 0))
    ttk.Radiobutton(f, text="Only my Tailscale devices (recommended)", variable=access_var,
                    value="tailscale").grid(row=1, column=1, sticky="w", padx=8, pady=(12, 0))
    ttk.Radiobutton(f, text="My Tailscale devices and anyone on this local network (needs a password)",
                    variable=access_var, value="network").grid(row=2, column=1, sticky="w", padx=8)
    ttk.Label(f, text="Password").grid(row=3, column=0, sticky="w", pady=(12, 0))
    ttk.Entry(f, textvariable=pw_var, show="\u2022", width=24).grid(row=3, column=1, sticky="w", padx=8,
                                                                    pady=(12, 0))
    pw_note = "A password is set. Type a new one to change it." if cfg["password_hash"] else \
        "Optional for Tailscale devices only. For the local network, TailWake makes one if you leave it empty."
    ttk.Label(f, text=pw_note, foreground="#666").grid(row=4, column=1, sticky="w", padx=8)
    if cfg["password_hash"]:
        ttk.Checkbutton(f, text="Remove the password", variable=clear_pw).grid(row=5, column=1, sticky="w", padx=8)
    ttk.Checkbutton(f, text="Keep checking status when nobody has the page open",
                    variable=bg_var).grid(row=6, column=1, sticky="w", padx=8, pady=(12, 0))
    ttk.Label(f, text="Off by default: regular pings can wake some sleeping PCs by themselves.",
              foreground="#666").grid(row=7, column=1, sticky="w", padx=8)
    ttk.Checkbutton(f, text="Show notifications (wake sent, device online)",
                    variable=notify_var).grid(row=8, column=1, sticky="w", padx=8, pady=(12, 0))
    for v in (port_var, access_var, pw_var, clear_pw, bg_var, notify_var):
        v.trace_add("write", lambda *a: mark_dirty())

    # ---- Tailscale
    tab = ttk.Frame(nb)
    nb.add(tab, text="Tailscale")
    ts_status = ttk.Label(tab, text="Checking Tailscale\u2026", wraplength=520, justify="left")
    ts_status.pack(anchor="w", **pad)
    url_frame = ttk.Frame(tab)
    url_frame.pack(fill="x", padx=10)
    ts_help = ttk.Label(tab, wraplength=520, justify="left", foreground="#555", text=(
        "Open the address on your phone or laptop while it is connected to Tailscale. Tip: on a phone, use "
        "\u201cAdd to Home Screen\u201d for a one-tap Wake button.\n\nThe HTTPS address uses Tailscale Serve: a "
        "https://\u2026ts.net link that only your tailnet can open. It needs HTTPS turned on for your tailnet "
        "(Tailscale admin console \u2192 DNS)."))
    ts_help.pack(anchor="w", **pad)
    ts_bar = ttk.Frame(tab)
    ts_bar.pack(fill="x", padx=10, pady=4)

    def show_ts(result):
        for w in url_frame.winfo_children():
            w.destroy()
        info, conf = result if isinstance(result, tuple) else ({}, None)
        if not info.get("installed"):
            ts_status.config(text="Tailscale isn't installed on this computer. Install it and sign in, then "
                                  "press Check again. Your phone needs Tailscale too.")
            return
        if not info.get("connected"):
            ts_status.config(text="Tailscale is installed but not connected (%s). Open Tailscale and sign in."
                             % (info.get("state") or "stopped"))
            return
        who = info.get("dns") or info.get("ip")
        try:
            port = int(port_var.get())
        except ValueError:
            port = cfg["port"]
        https = serve_urls(conf or {}, port)
        if https:
            serving = "The HTTPS address is on."
        elif conf is None:
            serving = "Couldn't check whether the HTTPS address is on."
        else:
            serving = "The HTTPS address is off."
        ts_status.config(text="Connected to Tailscale as %s. %s" % (who, serving))
        urls = page_urls(dict(cfg, port=port), info) + https
        for i, u in enumerate(urls):
            e = ttk.Entry(url_frame, width=46)
            e.insert(0, u)
            e.config(state="readonly")
            e.grid(row=i, column=0, sticky="w", pady=2)
            ttk.Button(url_frame, text="Copy", command=lambda u=u: (root.clipboard_clear(), root.clipboard_append(u))
                       ).grid(row=i, column=1, padx=4)
            ttk.Button(url_frame, text="Open", command=lambda u=u: webbrowser.open(u)).grid(row=i, column=2)

    def check_ts():
        ts_status.config(text="Checking Tailscale\u2026")
        in_background(lambda: (tailscale_info(), serve_config()), show_ts)

    def serve(on):
        try:
            port = int(port_var.get())
        except ValueError:
            port = cfg["port"]

        def done(r):
            messagebox.showinfo("Tailscale Serve", r[1] if not isinstance(r, Exception) else str(r), parent=root)
            check_ts()
        in_background(lambda: tailscale_serve(port, on), done)

    ttk.Button(ts_bar, text="Check again", command=check_ts).pack(side="left")
    ttk.Button(ts_bar, text="Turn HTTPS address on", command=lambda: serve(True)).pack(side="left", padx=6)
    ttk.Button(ts_bar, text="Turn it off", command=lambda: serve(False)).pack(side="left")
    ttk.Button(ts_bar, text="Get Tailscale",
               command=lambda: webbrowser.open("https://tailscale.com/download")).pack(side="right")
    check_ts()

    # ---- App
    tab = ttk.Frame(nb)
    nb.add(tab, text="App")
    run_status = ttk.Label(tab, text="", wraplength=520, justify="left")
    run_status.pack(anchor="w", **pad)
    abar = ttk.Frame(tab)
    abar.pack(fill="x", padx=10)
    auto_var = tk.BooleanVar(value=autostart_enabled())

    def show_run(status):
        if isinstance(status, dict):
            if status.get("serving"):
                run_status.config(text="TailWake is running. The web page is on (port %d)." % status["port"])
            else:
                run_status.config(text="TailWake is running, but the web page is off. %s" % status.get("error", ""))
        else:
            run_status.config(text="TailWake is not running.")

    def update_run():
        in_background(lambda: control("status", timeout=3), show_run)

    def do(cmd):
        if cmd == "start":
            in_background(start_background, show_run)
        elif cmd == "stop":
            in_background(lambda: (control("stop"), time.sleep(0.8), control("status", timeout=2))[2], show_run)
        else:
            in_background(lambda: control(cmd), show_run)

    ttk.Button(abar, text="Start", command=lambda: do("start")).pack(side="left")
    ttk.Button(abar, text="Stop", command=lambda: do("stop")).pack(side="left", padx=6)
    ttk.Button(abar, text="Restart web page", command=lambda: do("restart")).pack(side="left")

    def toggle_auto():
        try:
            message = autostart_on() if auto_var.get() else autostart_off()
            messagebox.showinfo("Start at login", message, parent=root)
        except Exception as e:
            auto_var.set(autostart_enabled())
            messagebox.showerror("Start at login", str(e), parent=root)

    ttk.Checkbutton(tab, text="Start TailWake when I log in", variable=auto_var,
                    command=toggle_auto).pack(anchor="w", padx=10, pady=(14, 4))
    lbar = ttk.Frame(tab)
    lbar.pack(fill="x", padx=10, pady=8)
    ttk.Button(lbar, text="Open log", command=lambda: os.path.exists(log_path()) and open_path(log_path())
               ).pack(side="left")
    ttk.Button(lbar, text="Open settings folder", command=lambda: open_path(config_dir())).pack(side="left", padx=6)
    ttk.Label(tab, text="TailWake %s \u00b7 %s" % (VERSION, REPO), foreground="#666").pack(anchor="w", **pad)
    update_run()

    def show_password(password):
        win = tk.Toplevel(root)
        win.title("TailWake password")
        win.transient(root)
        win.resizable(False, False)
        ttk.Label(win, wraplength=380, justify="left", text=(
            "Opening the page from the local network needs a password, so TailWake made one. Keep it somewhere "
            "safe: it is only shown now. You can change it on the Web page tab.")).pack(anchor="w", padx=12, pady=10)
        e = ttk.Entry(win, width=30, font=("TkFixedFont", 12))
        e.insert(0, password)
        e.config(state="readonly")
        e.pack(anchor="w", padx=12)
        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=12, pady=10)
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        ttk.Button(bar, text="Copy", command=lambda: (root.clipboard_clear(), root.clipboard_append(password))
                   ).pack(side="right", padx=6)
        win.grab_set()

    # ---- bottom bar
    dirty = {"v": False}
    bottom = ttk.Frame(root)
    bottom.pack(fill="x", padx=8, pady=8)
    saved_label = ttk.Label(bottom, text="")
    saved_label.pack(side="left")

    def mark_dirty():
        dirty["v"] = True
        saved_label.config(text="Unsaved changes")

    loaded = {"devices": {d["id"]: dict(d) for d in cfg["devices"]}, "port": cfg["port"], "access": cfg["access"],
              "background_checks": cfg["background_checks"], "notifications": cfg["notifications"]}

    def save():
        try:
            port = int(port_var.get())
        except ValueError:
            port = None
        problem = port_problem(port)
        if problem:
            messagebox.showerror("Settings", problem, parent=root)
            return False
        # Start from the file as it is now and apply only what was changed in this window, so changes made
        # meanwhile (`tailwake add`, `tailwake config`, another settings window) are kept.
        fresh = load_config()
        window = {d["id"]: d for d in cfg["devices"]}
        for did, before in loaded["devices"].items():
            if did not in window:                                       # removed here
                fresh["devices"] = [d for d in fresh["devices"] if d["id"] != did]
        for d in cfg["devices"]:
            before = loaded["devices"].get(d["id"])
            if before == d:
                continue                                                # unchanged here
            on_disk = next((x for x in fresh["devices"] if x["id"] == d["id"]), None)
            if on_disk is not None:
                on_disk.update({k: d[k] for k in ("name", "mac", "ip", "broadcast")})
            else:                                                       # added here (or removed meanwhile)
                fresh["devices"].append(dict(d))
        edits = {"port": port, "access": access_var.get(), "background_checks": bg_var.get(),
                 "notifications": notify_var.get()}
        fresh.update({k: v for k, v in edits.items() if v != loaded[k]})
        if clear_pw.get():
            if fresh["access"] == "network":
                messagebox.showerror("Settings", "Access from the local network needs a password. Switch to "
                                     "\u201cOnly my Tailscale devices\u201d to remove it.", parent=root)
                return False
            set_password(fresh, "")
        elif pw_var.get():
            set_password(fresh, pw_var.get())
        new_password = ensure_network_password(fresh)
        save_config(fresh)
        cfg.clear()
        cfg.update(fresh)
        loaded.update(devices={d["id"]: dict(d) for d in cfg["devices"]}, **{k: cfg[k] for k in edits})
        refresh_tree()
        port_var.set(str(cfg["port"]))                                  # show what is saved, incl. changes from
        access_var.set(cfg["access"])                                   # elsewhere
        bg_var.set(cfg["background_checks"])
        notify_var.set(cfg["notifications"])
        pw_var.set("")
        clear_pw.set(False)
        dirty["v"] = False
        reply = control("reload")
        if not reply and fresh["port"] != loaded_port["v"]:
            serve_follow_port(loaded_port["v"], fresh["port"])
        loaded_port["v"] = fresh["port"]
        saved_label.config(text="Saved." if reply else "Saved. (TailWake isn't running: press Start on the App tab.)")
        if reply:
            show_run(reply)
        if new_password:
            show_password(new_password)
        check_ts()
        return True

    loaded_port = {"v": cfg["port"]}

    def close():
        if dirty["v"]:
            answer = messagebox.askyesnocancel("TailWake", "Save your changes?", parent=root)
            if answer is None or (answer and not save()):
                return
        root.destroy()

    ttk.Button(bottom, text="Close", command=close).pack(side="right")
    ttk.Button(bottom, text="Save", command=save).pack(side="right", padx=6)
    root.protocol("WM_DELETE_WINDOW", close)
    tabs = {"devices": 0, "web": 1, "tailscale": 2, "app": 3}
    if start_tab in tabs:
        nb.select(tabs[start_tab])
    if not cfg["devices"]:
        root.after(300, lambda: saved_label.config(text="Start here: add the computer you want to wake."))
    root.lift()
    root.attributes("-topmost", True)
    root.after(400, lambda: root.attributes("-topmost", False))
    root.mainloop()
    return 0


def _tk_icon_png() -> bytes:
    """A tiny PNG of the app icon for the settings window (standard library only)."""
    import struct
    import zlib
    size = 32
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            dx, dy = x - 15.5, y - 15.5
            r = (dx * dx + dy * dy) ** 0.5
            if r > 15:
                row += bytes((0, 0, 0, 0))
                continue
            white = (7 <= r <= 10 and not (dy < -3 and abs(dx) < 5)) or (abs(dx) < 1.6 and -12 < dy < 0)
            row += bytes((255, 255, 255, 255)) if white else bytes((18, 105, 95, 255))
        rows.append(bytes(row))
    raw = zlib.compress(b"".join(rows))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


# ------------------------------------------------------------------------------------------------------- the CLI

def setup_logging(foreground: bool) -> None:
    os.makedirs(config_dir(), exist_ok=True)
    log.setLevel(logging.DEBUG if os.environ.get("TAILWAKE_DEBUG") else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(log_path(), maxBytes=512 * 1024, backupCount=1, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(fh)
    if foreground and sys.stderr and sys.stderr.isatty():
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
        log.addHandler(sh)


def print_status(status) -> None:
    if not status:
        print("TailWake is not running. Start it with: tailwake start")
        return
    print("TailWake %s is running (pid %s)." % (status.get("version"), status.get("pid")))
    if status.get("serving"):
        print("Web page: " + (", ".join(status["urls"]) or "http://127.0.0.1:%d/ (Tailscale not connected)"
                              % status["port"]))
    else:
        print("Web page: off. " + (status.get("error") or "Turn it on from the tray icon or `tailwake restart`."))
    for d in status.get("devices", []):
        print("  %-20s %-9s %s" % (d["name"], d["label"], d["detail"]))
    if not status.get("devices"):
        print("  No devices yet: run `tailwake settings` or `tailwake add NAME MAC`.")


def cmd_default(args) -> int:
    status = control("status")
    if status:
        open_settings_window()
        return 0
    status = start_background()
    if not status:
        print("TailWake didn't start. See the log: " + log_path())
        return 1
    if sys.stdout and sys.stdout.isatty():
        print_status(status)
    if not status.get("devices"):
        open_settings_window()
    return 0


def cmd_run(args) -> int:
    setup_logging(foreground=True)
    if control("status"):
        log.info("TailWake is already running")
        return 0
    log.info("TailWake %s starting (%s, Python %s)", VERSION, platform.platform(), platform.python_version())
    if os.environ.get("TAILWAKE_DEBUG"):
        import faulthandler
        dump = open(os.path.join(config_dir(), "stacks.txt"), "w")
        faulthandler.dump_traceback_later(6, repeat=False, file=dump)
    return App().run(tray=not args.no_tray)


def cmd_start(args) -> int:
    was = control("status")
    status = was or start_background()
    if not status:
        print("TailWake didn't start. See the log: " + log_path())
        return 1
    print("TailWake was already running." if was else "TailWake started.")
    print_status(status)
    return 0


def cmd_stop(args) -> int:
    if control("stop") is None:
        print("TailWake is not running.")
        return 0
    for _ in range(25):
        time.sleep(0.2)
        if control("status", timeout=1) is None:
            print("TailWake stopped.")
            return 0
    print("TailWake didn't stop in time.")
    return 1


def cmd_restart(args) -> int:
    cmd_stop(args)
    return cmd_start(args)


def cmd_status(args) -> int:
    status = control("check" if args.check else "status", timeout=30)
    if args.json:
        print(json.dumps(status or {"running": False}, indent=2))
    else:
        print_status(status)
    return 0 if status else 3


def cmd_wake(args) -> int:
    cfg = load_config()
    if not cfg["devices"]:
        print("No devices yet. Add one with `tailwake add NAME MAC` or `tailwake settings`.")
        return 1
    if not args.device:
        if len(cfg["devices"]) > 1:
            print("Which one? " + ", ".join(d["name"] for d in cfg["devices"]))
            return 1
        args.device = cfg["devices"][0]["id"]
    d = find_device(cfg, args.device)
    if not d:
        print("No device called %r. Devices: %s" % (args.device, ", ".join(x["name"] for x in cfg["devices"])))
        return 1
    reply = control("wake", {"id": d["id"]})
    if reply:
        print(reply.get("message"))
        return 0 if reply.get("ok") else 1
    try:
        print(send_wake(d))
        return 0
    except OSError as e:
        print("Couldn't send the wake packet: %s" % e)
        return 1


def cmd_devices(args) -> int:
    cfg = load_config()
    if not cfg["devices"]:
        print("No devices yet. Add one with `tailwake add NAME MAC [--ip IP]` or `tailwake settings`.")
        print_invalid_devices(cfg)
        return 0
    for d in cfg["devices"]:
        print("%-20s %s  %s" % (d["name"], d["mac"].upper(), d["ip"] or "-"))
    print_invalid_devices(cfg)
    return 0


def print_invalid_devices(cfg: dict) -> None:
    for d in cfg["_invalid_devices"]:
        name = (d.get("name") if isinstance(d, dict) else None) or repr(d)[:40]
        mac = d.get("mac") if isinstance(d, dict) else ""
        print("%-20s skipped: the MAC address %r can't be read. Fix it in %s or with `tailwake add`."
              % (name, mac, config_path()))


def cmd_add(args) -> int:
    cfg = load_config()
    mac = normalize_mac(args.mac)
    if not mac:
        print("That MAC address doesn't look right (six pairs, e.g. 00:1A:2B:3C:4D:5E).")
        return 1
    for value, what in ((args.ip, "IP"), (args.broadcast, "broadcast")):
        if value and not is_ipv4(value):
            print("The %s address should look like 192.168.1.20." % what)
            return 1
    existing = find_device(cfg, args.name)
    if existing and existing["name"].lower() == args.name.lower():
        existing.update(mac=mac, ip=args.ip or existing["ip"], broadcast=args.broadcast or existing["broadcast"])
        print("Updated %s." % args.name)
    else:
        cfg["devices"].append({"id": secrets.token_hex(4), "name": args.name, "mac": mac, "ip": args.ip or "",
                               "broadcast": args.broadcast or ""})
        print("Added %s." % args.name)
    save_config(cfg)
    control("reload")
    return 0


def cmd_remove(args) -> int:
    cfg = load_config()
    d = find_device(cfg, args.name)
    if not d:
        print("No device called %r." % args.name)
        return 1
    cfg["devices"].remove(d)
    save_config(cfg)
    control("reload")
    print("Removed %s." % d["name"])
    return 0


def cmd_scan(args) -> int:
    print("Looking for devices on your network (only devices that are on show up)\u2026")
    rows = scan_network()
    if not rows:
        print("Nothing found.")
        return 1
    for ip, mac, name, state in rows:
        print("%-16s %s  %s" % (ip, mac.upper(), name))
    print("\nAdd one with: tailwake add NAME MAC --ip IP")
    return 0


def cmd_config(args) -> int:
    cfg = load_config()
    old_port = cfg["port"]
    changed = False
    if args.port is not None:
        problem = port_problem(args.port)
        if problem:
            print(problem)
            return 1
        cfg["port"], changed = args.port, True
    if args.access:
        cfg["access"], changed = args.access, True
    if args.background_checks is not None:
        cfg["background_checks"], changed = args.background_checks == "on", True
    if args.password is not None or args.no_password:
        if args.no_password:
            if cfg["access"] == "network":
                print("Access from the local network needs a password. Use --access tailscale to remove it.")
                return 1
            set_password(cfg, "")
        else:
            pw = args.password
            if pw == "":
                import getpass
                pw = getpass.getpass("New password (empty = no password): ")
            if not pw and cfg["access"] == "network":
                print("Access from the local network needs a password.")
                return 1
            set_password(cfg, pw)
        changed = True
    new_password = ensure_network_password(cfg)
    changed = changed or bool(new_password)
    if changed:
        save_config(cfg)
        if control("reload") is None and cfg["port"] != old_port:
            print(serve_follow_port(old_port, cfg["port"]) or "", end="")
        print("Saved.")
    if new_password:
        print("Local network access needs a password, so TailWake made one: %s\n"
              "Change it with: tailwake config --password" % new_password)
    print("port:              %d" % cfg["port"])
    print("access:            %s" % ("Tailscale devices only" if cfg["access"] == "tailscale"
                                     else "Tailscale devices + local network"))
    print("password:          %s" % ("set" if cfg["password_hash"] else "none"))
    print("background checks: %s" % ("on" if cfg["background_checks"] else "off"))
    print("settings file:     %s" % config_path())
    return 0


def cmd_autostart(args) -> int:
    if args.action == "on":
        print(autostart_on(service=args.service))
    elif args.action == "off":
        print(autostart_off())
    else:
        print("Start at login is %s." % ("on" if autostart_enabled() else "off"))
    return 0


def cmd_tailscale(args) -> int:
    if args.action in ("serve-on", "serve-off"):
        ok, message = tailscale_serve(load_config()["port"], args.action == "serve-on")
        print(message)
        return 0 if ok else 1
    info = tailscale_info()
    if not info["installed"]:
        print("Tailscale isn't installed. Get it from https://tailscale.com/download")
        return 1
    if not info["connected"]:
        print("Tailscale is installed but not connected (%s)." % (info["state"] or "stopped"))
        return 1
    print("Connected to Tailscale as %s (%s)." % (info["dns"] or "?", info["ip"]))
    cfg = load_config()
    for u in page_urls(cfg, info) + serve_urls(serve_config() or {}, cfg["port"]):
        print("Page: " + u)
    return 0


def cmd_selftest(args) -> int:
    """Quick offline checks (used by CI)."""
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("0:1a:2b:3c:4d:5e") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("001a.2b3c.4d5e") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("001A2B3C4D5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("00:1a:2b:3c:4d") is None and normalize_mac("zz:1a:2b:3c:4d:5e") is None
    p = magic_packet("02:00:00:00:00:01")
    assert len(p) == 102 and p[:6] == b"\xff" * 6 and p[6:12] == bytes.fromhex("020000000001")
    assert parse_ip_neigh("192.168.1.5 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE\n"
                          "192.168.1.6 dev eth0 lladdr 02:00:00:00:00:02 STALE\n"
                          "192.168.1.7 dev eth0  FAILED\n") == [
        ("192.168.1.5", "02:00:00:00:00:01", "ok"), ("192.168.1.6", "02:00:00:00:00:02", "stale")]
    assert parse_arp_a("? (192.168.1.5) at 2:0:0:0:0:1 on en0 ifscope [ethernet]\n"
                       "? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n") == [
        ("192.168.1.5", "02:00:00:00:00:01", "unknown")]
    assert parse_arp_a("  192.168.1.15          00-1a-2b-3c-4d-5e     dynamic\n") == [
        ("192.168.1.15", "00:1a:2b:3c:4d:5e", "unknown")]
    assert parse_netsh("192.168.1.15                                  00-1a-2b-3c-4d-5e  Reachable\n"
                       "192.168.1.16                                  00-1a-2b-3c-4d-5f  Stale\n"
                       "192.168.1.17                                  00-00-00-00-00-00  Unreachable\n") == [
        ("192.168.1.15", "00:1a:2b:3c:4d:5e", "ok"), ("192.168.1.16", "00:1a:2b:3c:4d:5f", "stale")]
    assert parse_proc_arp("IP address HW type Flags HW address Mask Device\n"
                          "192.168.1.5 0x1 0x2 02:00:00:00:00:01 * eth0\n192.168.1.6 0x1 0x0 00:00:00:00:00:00 * eth0\n"
                          ) == [("192.168.1.5", "02:00:00:00:00:01", "unknown")]
    assert in_tailscale_range("100.101.102.103") and not in_tailscale_range("100.128.0.1")
    assert in_tailscale_range("fd7a:115c:a1e0::1") and not in_tailscale_range("192.168.1.1")
    t = broadcast_targets({"mac": "02:00:00:00:00:01", "ip": "192.168.7.20", "broadcast": "192.168.7.127"})
    assert t[0] == "192.168.7.127" and "255.255.255.255" in t and "192.168.7.255" in t and "192.168.7.20" in t
    cfg = dict(DEFAULTS)
    set_password(cfg, "hunter2")
    assert check_password(cfg, "hunter2") and not check_password(cfg, "nope")
    assert _tk_icon_png().startswith(b"\x89PNG")
    assert _desktop_quote("/a b/c") == '"/a b/c"' and _desktop_quote("/usr/bin/python3") == "/usr/bin/python3"
    print("self-test OK")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="tailwake", description="Wake your computers from anywhere over Tailscale. With no command: start "
                                     "TailWake in the background (or open its settings if it is running).")
    ap.add_argument("--version", action="version", version="TailWake " + VERSION)
    sub = ap.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.add_parser("help", help="show this help")
    p = sub.add_parser("run", help="run in the foreground (used for start at login)")
    p.add_argument("--no-tray", action="store_true", help="no tray icon (servers, Raspberry Pi, ...)")
    sub.add_parser("start", help="start in the background")
    sub.add_parser("stop", help="stop the running TailWake")
    sub.add_parser("restart", help="stop and start again")
    p = sub.add_parser("status", help="is it running, the web address and device status")
    p.add_argument("--check", action="store_true", help="check the devices now")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = sub.add_parser("settings", help="open the settings window")
    p.add_argument("tab", nargs="?", choices=("devices", "web", "tailscale", "app"), help="open on this tab")
    p = sub.add_parser("wake", help="wake a device")
    p.add_argument("device", nargs="?", help="device name (not needed if there is only one)")
    sub.add_parser("devices", help="list your devices")
    p = sub.add_parser("add", help="add or update a device")
    p.add_argument("name")
    p.add_argument("mac", help="MAC address, e.g. 00:1A:2B:3C:4D:5E")
    p.add_argument("--ip", help="its local IP address (recommended: lets TailWake show online/offline)")
    p.add_argument("--broadcast", help="broadcast address, only if waking doesn't work otherwise")
    p = sub.add_parser("remove", help="remove a device")
    p.add_argument("name")
    sub.add_parser("scan", help="list devices on this local network (to find a MAC address)")
    p = sub.add_parser("config", help="show or change web page settings")
    p.add_argument("--port", type=int)
    p.add_argument("--access", choices=("tailscale", "network"),
                   help="tailscale: Tailscale devices only; network: also this local network")
    p.add_argument("--password", nargs="?", const="", help="set a password (asks if not given)")
    p.add_argument("--no-password", action="store_true", help="remove the password")
    p.add_argument("--background-checks", choices=("on", "off"), help="check status even when nobody looks")
    p = sub.add_parser("autostart", help="start at login: on, off or status")
    p.add_argument("action", choices=("on", "off", "status"))
    p.add_argument("--service", action="store_true", help="Linux: use a systemd user service even on a desktop")
    p = sub.add_parser("tailscale", help="Tailscale status, or turn the HTTPS address on/off")
    p.add_argument("action", nargs="?", choices=("status", "serve-on", "serve-off"), default="status")
    sub.add_parser("selftest", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.cmd == "help":
        ap.print_help()
        return 0
    handlers = {None: cmd_default, "run": cmd_run, "start": cmd_start, "stop": cmd_stop, "restart": cmd_restart,
                "status": cmd_status, "settings": lambda a: settings_window(a.tab or ""), "wake": cmd_wake,
                "devices": cmd_devices, "add": cmd_add, "remove": cmd_remove, "scan": cmd_scan, "config": cmd_config,
                "autostart": cmd_autostart, "tailscale": cmd_tailscale, "selftest": cmd_selftest}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
