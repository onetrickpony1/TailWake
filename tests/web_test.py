"""Tests for the web page's rules and the settings file, without a tray icon or a real device:
who may open the page, the Host check, login + cookie + lock-out, the X-TailWake header, the config round-trip,
and reading Tailscale Serve's settings. Run: python tests/web_test.py"""
import http.client
import importlib.util
import ipaddress
import json
import os
import socket
import tempfile
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["TAILWAKE_HOME"] = tempfile.mkdtemp(prefix="tailwake-webtest-")
spec = importlib.util.spec_from_file_location("tailwake", os.path.join(os.path.dirname(HERE), "tailwake.py"))
tw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tw)

LAN = ipaddress.ip_network("192.168.50.0/24")
tw.local_networks = lambda max_age=60: [LAN]           # pretend this computer is on 192.168.50.0/24
tw.tailscale_info = lambda: {"installed": False, "connected": False, "ip": "", "dns": "", "state": ""}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check(name, cond, detail=""):
    if not cond:
        raise SystemExit("FAIL: %s %s" % (name, detail))
    print("ok   " + name)


# ---------------------------------------------------------------------------------------------- config round-trip

def test_config_round_trip():
    tw.write_json(tw.config_path(), {
        "port": 18001, "future_option": True, "secret": "abc",
        "devices": [{"id": "a1", "name": "Box", "mac": "02:00:00:00:00:01", "wol_port": 7},
                    {"id": "b2", "name": "Broken", "mac": "bad"}]})
    cfg = tw.load_config()
    check("valid device loaded", [d["name"] for d in cfg["devices"]] == ["Box"])
    check("invalid device kept aside", len(cfg["_invalid_devices"]) == 1)
    tw.save_config(cfg)
    raw = tw.read_json(tw.config_path())
    check("unknown top-level key kept", raw.get("future_option") is True, raw)
    check("unknown device field kept", raw["devices"][0].get("wol_port") == 7, raw)
    check("invalid device kept in file", any(d.get("mac") == "bad" for d in raw["devices"]), raw)
    check("no private keys written", not any(k.startswith("_") for k in raw), raw)
    cfg["devices"].append({"id": "c3", "name": "broken", "mac": "02:00:00:00:00:03", "ip": "", "broadcast": ""})
    tw.save_config(cfg)
    raw = tw.read_json(tw.config_path())
    check("re-added device replaces the unreadable one", not any(d.get("mac") == "bad" for d in raw["devices"]), raw)


def test_ports_and_passwords():
    check("port 80 refused", tw.port_problem(80) != "")
    check("port 1024 accepted", tw.port_problem(1024) == "")
    check("port 70000 refused", tw.port_problem(70000) != "")
    cfg = dict(tw.DEFAULTS, access="network")
    pw = tw.ensure_network_password(cfg)
    check("network access gets a password", pw and tw.check_password(cfg, pw) and not tw.check_password(cfg, "x"))
    check("existing password kept", tw.ensure_network_password(cfg) == "")
    check("tailscale-only needs none", tw.ensure_network_password(dict(tw.DEFAULTS)) == "")


def test_config_cli():
    check("config --port 80 refused", tw.main(["config", "--port", "80"]) == 1)
    check("config --access network", tw.main(["config", "--access", "network", "--no-password"]) == 1)
    check("config --access network makes a password", tw.main(["config", "--access", "network"]) == 0
          and tw.load_config()["password_hash"])
    check("no-password refused in network mode", tw.main(["config", "--no-password"]) == 1)
    tw.main(["config", "--access", "tailscale", "--no-password"])
    check("back to tailscale, no password", not tw.load_config()["password_hash"])


# ---------------------------------------------------------------------------------------------- who may connect

class FakeApp:
    def __init__(self, access="tailscale", password=""):
        self.cfg = dict(tw.DEFAULTS, access=access)
        tw.set_password(self.cfg, password)

    def host_names(self):
        return {"homebox", "homebox.local", "homebox.tail1234.ts.net"}


def allowed(ip, access="tailscale", password=""):
    h = object.__new__(tw.WebHandler)
    h.client_address = (ip, 50000)
    h.app = FakeApp(access, password)
    return h._allowed()


def test_allowed():
    for access, pw in (("tailscale", ""), ("network", "secret"), ("network", "")):
        check("loopback allowed (%s)" % access, allowed("127.0.0.1", access, pw) and allowed("::1", access, pw))
        check("tailnet allowed (%s)" % access, allowed("100.101.102.103", access, pw))
        check("public refused (%s)" % access, not allowed("8.8.8.8", access, pw))
        check("other private range refused (%s)" % access, not allowed("10.9.8.7", access, pw))
    check("LAN refused in tailscale mode", not allowed("192.168.50.20"))
    check("LAN allowed in network mode with a password", allowed("192.168.50.20", "network", "secret"))
    check("LAN refused in network mode without a password", not allowed("192.168.50.20", "network", ""))
    check("IPv4-mapped LAN", allowed("::ffff:192.168.50.20", "network", "secret"))


def test_cgnat_lan():
    old_nets, old_whois = tw.local_networks, tw.tailscale_whois
    tw.local_networks = lambda max_age=60: [ipaddress.ip_network("100.70.0.0/16")]
    try:
        tw.tailscale_whois = lambda ip: False
        check("CGNAT LAN address not trusted as Tailscale", not allowed("100.70.1.2"))
        tw.tailscale_whois = lambda ip: True
        check("CGNAT address confirmed by whois", allowed("100.70.1.2"))
        tw.tailscale_whois = lambda ip: False
        check("other 100.x not affected", allowed("100.101.1.2"))
    finally:
        tw.local_networks, tw.tailscale_whois = old_nets, old_whois


def host_ok(host):
    h = object.__new__(tw.WebHandler)
    h.app = FakeApp()
    h.headers = {"Host": host} if host is not None else {}
    return h._host_ok()


def test_host_names():
    for good in ("127.0.0.1:8002", "[::1]:8002", "localhost:8002", "100.101.102.103", "homebox:8002",
                 "HomeBox.local", "homebox.tail1234.ts.net", "homebox.tail1234.ts.net.:8002", None):
        check("host %r accepted" % good, host_ok(good))
    for bad in ("evil.example:18766", "homebox.evil.example", "localhost.evil.example", "ts.net"):
        check("host %r refused" % bad, not host_ok(bad))


def test_interface_parsers():
    check("ip -o addr", tw.parse_ip_addr(
        "2: enp8s0    inet 192.168.2.15/24 brd 192.168.2.255 scope global\n"
        "2: enp8s0    inet6 fe80::b00:8dfb:697c:32aa/64 scope link\n") == ["192.168.2.15/24",
                                                                         "fe80::b00:8dfb:697c:32aa/64"])
    check("ifconfig", tw.parse_ifconfig(
        "en0: flags=8863\n\tinet6 fe80::1c%en0 prefixlen 64 secured scopeid 0x4\n"
        "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n"
        "utun3: flags=8051\n\tinet 100.101.1.2 --> 100.101.1.2 netmask 0xffffffff\n") == [
        "192.168.1.20/24", "fe80::1c/64"])
    check("powershell lines", tw.parse_prefix_lines("192.168.1.20/24\r\nfe80::1%12/64\r\n\r\n") == [
        "192.168.1.20/24", "fe80::1/64"])


# ---------------------------------------------------------------------------------------------- tailscale serve

SERVE = {"TCP": {"443": {"HTTPS": True}},
         "Web": {"homebox.tail1234.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8765"}}}}}


def test_serve_parsing():
    check("other app on 443 -> 8443", tw.serve_free_port(SERVE, 8002) == 8443)
    check("nothing served -> 443", tw.serve_free_port({}, 8002) == 443)
    check("ours on 443 -> 443", tw.serve_free_port(SERVE, 8765) == 443)
    check("serve_urls for ours", tw.serve_urls(SERVE, 8765) == ["https://homebox.tail1234.ts.net/"])
    check("serve_urls for others", tw.serve_urls(SERVE, 8002) == [])
    full = {"TCP": {"443": {"HTTPS": True}, "8443": {"TCPForward": "127.0.0.1:22"}, "10000": {"HTTPS": True}},
            "Web": {"h:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:1"}}},
                    "h:10000": {"Handlers": {"/": {"Path": "/srv"}}}}}
    check("all ports taken -> None", tw.serve_free_port(full, 8002) is None)
    check("localhost target", tw._local_port("localhost:8002") == 8002 and tw._local_port("https://x:1") is None)


# ---------------------------------------------------------------------------------------------- running server

class Server:
    def __init__(self, password=""):
        tw.write_json(tw.config_path(), {"port": free_port(), "secret": "s" * 32,
                                         "devices": [{"id": "d1", "name": "Test Box", "mac": "02:00:00:00:00:01",
                                                      "ip": "192.0.2.10"}]})
        cfg = tw.load_config()
        tw.set_password(cfg, password)
        tw.save_config(cfg)
        self.app = tw.App()
        self.app.host_names = lambda: {"homebox"}
        self.app.check_all = lambda: None                 # no pings in tests
        assert self.app.start_server(), self.app.server_error
        self.port = self.app.cfg["port"]

    def request(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = dict(headers or {})
        if host:
            h["Host"] = host
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def stop(self):
        self.app.stop_server()


def login(srv, password):
    return srv.request("POST", "/login", urllib.parse.urlencode({"password": password}),
                       {"Content-Type": "application/x-www-form-urlencoded"})


def test_server_no_password():
    srv = Server()
    try:
        check("status 200", srv.request("GET", "/api/status")[0] == 200)
        check("foreign Host refused", srv.request("GET", "/api/status", host="evil.example:%d" % srv.port)[0] == 421)
        check("foreign Host refused on wake", srv.request(
            "POST", "/api/wake", json.dumps({"id": "Test Box"}), {"X-TailWake": "1"}, host="evil.example")[0] == 421)
        check("own name accepted", srv.request("GET", "/api/status", host="homebox:%d" % srv.port)[0] == 200)
        check("wake without X-TailWake -> 400", srv.request("POST", "/api/wake", json.dumps({"id": "Test Box"}))[0]
              == 400)
    finally:
        srv.stop()


def test_server_password():
    srv = Server(password="correct horse")
    try:
        check("page shows login", b"Password needed" in srv.request("GET", "/")[2])
        check("status 401 without cookie", srv.request("GET", "/api/status")[0] == 401)
        check("wake 401 without cookie", srv.request("POST", "/api/wake", json.dumps({"id": "Test Box"}),
                                                     {"X-TailWake": "1"})[0] == 401)
        code, headers, _ = login(srv, "correct horse")
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        check("right password sets a cookie", code == 303 and cookie.startswith("tailwake="))
        check("cookie works", srv.request("GET", "/api/status", headers={"Cookie": cookie})[0] == 200)
        check("bad cookie refused", srv.request("GET", "/api/status", headers={"Cookie": "tailwake=x"})[0] == 401)
        check("wrong password -> 401", login(srv, "nope")[0] == 401)

        srv.app.logins = tw.LoginGuard()
        results = []

        def guess():
            try:
                results.append(login(srv, "wrong")[0])
            except OSError as e:
                results.append(repr(e))
        threads = [threading.Thread(target=guess) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("parallel guesses all answered", len(results) == 40 and all(isinstance(r, int) for r in results), results)
        check("parallel guesses get 429", results.count(429) >= 35, results)
        check("at most 5 guesses checked", results.count(401) <= 5, results)
        check("locked out even with the right password", login(srv, "correct horse")[0] == 429)
    finally:
        srv.stop()


def test_login_guard():
    g = tw.LoginGuard(tries=3, first_lock=60, max_lock=3600, global_tries=10)
    check("first tries allowed", [g.attempt("a") for _ in range(3)] == [0, 0, 0])
    check("then locked", g.attempt("a") > 0)
    check("other address still fine", g.attempt("b") == 0)
    g.by_client["a"]["until"] = 0
    check("one more after the lock-out", g.attempt("a") == 0)
    check("lock-out doubles", g.by_client["a"]["lock"] == 120)
    g.success("b")
    check("success clears", "b" not in g.by_client)
    for i in range(10):
        g.attempt("c%d" % i)
    check("global cap", g.attempt("zz") > 0)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print("--", name)
            fn()
    print("web tests OK")


if __name__ == "__main__":
    main()
