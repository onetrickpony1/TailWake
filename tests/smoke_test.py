"""End-to-end check without a tray icon or a real device: start TailWake in the background, open its page, send a
wake packet to a made-up MAC address, stop it. Run: python tests/smoke_test.py"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "tailwake.py")
PORT = 18765


def tw(*args, check=True):
    p = subprocess.run([sys.executable, APP, *args], capture_output=True, text=True, timeout=60)
    print("$ tailwake", " ".join(args), "->", p.returncode, "\n" + p.stdout + p.stderr)
    if check and p.returncode != 0:
        raise SystemExit("command failed: %s" % " ".join(args))
    return p


def main():
    os.environ["TAILWAKE_HOME"] = tempfile.mkdtemp(prefix="tailwake-test-")
    os.environ["TAILWAKE_DEBUG"] = "1"
    os.environ.pop("DISPLAY", None)
    os.environ.pop("WAYLAND_DISPLAY", None)
    tw("add", "Test Box", "02:00:00:00:00:01", "--ip", "192.0.2.10")
    tw("config", "--port", str(PORT))
    try:
        tw("start")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:%d/" % PORT, timeout=10) as r:
            assert r.status == 200 and b"TailWake" in r.read()
        with opener.open("http://127.0.0.1:%d/api/status" % PORT, timeout=30) as r:
            data = json.loads(r.read())
            assert data["devices"][0]["name"] == "Test Box", data
        req = urllib.request.Request("http://127.0.0.1:%d/api/wake" % PORT, method="POST",
                                     data=json.dumps({"id": "Test Box"}).encode(),
                                     headers={"X-TailWake": "1", "Content-Type": "application/json"})
        with opener.open(req, timeout=10) as r:
            assert json.loads(r.read())["ok"]
        tw("status")
        tw("wake", "Test Box")
    finally:
        tw("stop", check=False)
        log = os.path.join(os.environ["TAILWAKE_HOME"], "tailwake.log")
        for name in (log, os.path.join(os.environ["TAILWAKE_HOME"], "stacks.txt")):
            if os.path.exists(name):
                print(open(name, encoding="utf-8").read())
    assert tw("status", check=False).returncode == 3, "still running after stop"
    print("smoke test OK")


if __name__ == "__main__":
    main()
