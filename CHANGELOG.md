# Changelog

## 1.1.0 - 2026-11-14

Security
- Wrong passwords are now really rate-limited: five tries per address, then a lock-out of 1 minute that doubles up to
  1 hour, plus a cap of 30 tries a minute overall. Tries are counted before the check, so parallel guesses don't get
  through (#1).
- The page only answers requests addressed to an IP address, `localhost`, this computer's name or its MagicDNS name.
  This stops DNS rebinding from other websites (#2).
- Local network access needs a password: TailWake makes one if none is set and shows it once. It only lets in this
  computer's own local networks, not every private range. A 100.x address on a local network that uses those
  addresses is checked with `tailscale whois` (#3).

Fixes
- Saving settings keeps config fields and device fields this version doesn't know, and keeps devices with an
  unreadable MAC address in the file (they are listed as skipped) (#4).
- "Turn HTTPS address on" no longer replaces something else that Tailscale Serve shares on port 443: TailWake uses
  8443 or 10000 instead. "Turn it off" removes only TailWake's own entry (#5).
- Changing the port moves the HTTPS address to the new port. The Tailscale tab shows whether the HTTPS address is
  really on (#6).
- The installers download and check the new version before stopping or replacing anything, so a failed download
  leaves the installed TailWake as it was (#7).
- Saving in the settings window only applies what was changed there, so devices and settings changed meanwhile from
  the command line are kept (#8).
- The port must be 1024 to 65535 in both the settings window and `tailwake config` (#9).

Other
- Python 3.10 or newer is now needed (3.9 is past its end of life). CI tests 3.10 and 3.14 on Windows, macOS and
  Linux (#10).
- New tests for the page's access rules, Host check, login, cookie, lock-out, wake header, config round-trip and
  Tailscale Serve handling (#11).

## 1.0.0 - 2026-11-12

First public version.

- Background app with a tray / menu-bar icon on Windows, macOS and Linux; runs without one on headless machines.
- Phone-friendly wake page for your Tailscale devices, with online / offline status for each device.
- Settings window: devices (with Find on network and Look up MAC from IP), web page access and password,
  Tailscale status and addresses, Tailscale Serve HTTPS address, start / stop, start at login.
- Command line: start, stop, restart, status, wake, add, remove, scan, config, autostart, tailscale.
- Start at login on Windows (sign-in), macOS (LaunchAgent) and Linux (autostart entry or systemd user service).
- One-line installers (install.sh, install.ps1) that ask before installing anything and keep the tray packages in
  TailWake's own folder. Licensed under the GNU GPL v3.0 or later.
