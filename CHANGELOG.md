# Changelog

## 1.0.0 — 2026-11-12

First public version.

- Background app with a tray / menu-bar icon on Windows, macOS and Linux; runs without one on headless machines.
- Phone-friendly wake page for your Tailscale devices, with online / offline status for each device.
- Settings window: devices (with Find on network and Look up MAC from IP), web page access and password,
  Tailscale status and addresses, Tailscale Serve HTTPS address, start / stop, start at login.
- Command line: start, stop, restart, status, wake, add, remove, scan, config, autostart, tailscale.
- Start at login on Windows (sign-in), macOS (LaunchAgent) and Linux (autostart entry or systemd user service).
- One-line installers (install.sh, install.ps1) that ask before installing anything and keep the tray packages in
  TailWake's own folder. Licensed under the GNU GPL v3.0 or later.
