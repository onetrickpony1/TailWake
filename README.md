# TailWake

Wake your computers from anywhere, over [Tailscale](https://tailscale.com). TailWake runs quietly in the background on
one always-on computer at home (a laptop, a mini PC, a Raspberry Pi) and serves a small, phone-friendly page to your
Tailscale devices. Tap **Wake** and it sends a Wake-on-LAN magic packet on its local network.

No port forwarding, no cloud service, no account: only devices signed in to your own tailnet can open the page.

## Features

- **One file, standard-library Python.** Tray icon through `pystray` + `Pillow`, installed privately by the installer.
- **Tray / menu-bar icon** on Windows, macOS and Linux: wake each device, see if it is online, open or copy the page
  address, turn the page off and on, start at login, quit. Green when a device is online, grey when not, amber when
  the page is off.
- **Settings window** to add the computers you want to wake. **Find on network** lists the devices that are on, so
  you can pick one instead of typing its MAC address; **Look up MAC from IP** does the same for one address.
- **Phone page** with online / offline status for every device, a Wake button, and live "waking… online" feedback.
  Works in light and dark mode; add it to your home screen for a one-tap button.
- **Tailscale built in:** shows the MagicDNS and 100.x addresses, answers only Tailscale devices by default, and can
  turn on a tailnet-only `https://…ts.net` address (Tailscale Serve) with one button.
- **Optional password**, optional access from the local network as well, notifications when a woken device comes up.
- **Start at login** with one click: Windows sign-in, macOS LaunchAgent, Linux autostart or a systemd user service
  for computers without a desktop.
- **Command line** for everything: `start`, `stop`, `restart`, `status`, `wake`, `add`, `scan`, `autostart`…

## Install

One line, no admin rights needed. It checks for Python 3.9+ with tkinter and **asks before installing anything that
is missing**, keeps the tray packages in TailWake's own folder, adds a `tailwake` command and a menu entry, and offers
start at login.

**Windows** (PowerShell):
```
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/onetrickpony1/tailwake/main/install.ps1 | iex"
```

**Linux and macOS** (Terminal):
```
curl -LsSf https://raw.githubusercontent.com/onetrickpony1/tailwake/main/install.sh | sh
```

Run the same line again to update. Or skip the installer: `pip install pystray Pillow` (optional) and run
`python3 tailwake.py`.

You also need **Tailscale** on this computer and on your phone or laptop: <https://tailscale.com/download>.

## Set up

1. Start TailWake (from the menu, or run `tailwake`). The first time, the settings window opens.
2. **Devices → Find on network…** with the computer you want to wake switched **on**. Pick it and press Use, then OK.
   Its IP address is optional but recommended: it lets TailWake show online / offline.
3. **Save.** The **Tailscale** tab shows the address to open, for example `http://my-pc.tail1234.ts.net:8002/`.
4. Open that address on your phone (with Tailscale connected) and tap Wake.

The computer you wake must have Wake-on-LAN turned on: in its BIOS/UEFI, and on Windows also in the network adapter's
Power Management and Advanced settings ("Wake on Magic Packet"). A wired Ethernet connection is the most reliable;
most Wi-Fi adapters can't be woken.

## Use

- **Tray icon:** click it for the menu (on Windows a left click opens the page).
- **Phone:** the page refreshes status by itself while it is open.
- **Command line:**

```
tailwake                     start in the background, or open settings if it is already running
tailwake settings [TAB]      settings window (devices, web, tailscale, app)
tailwake start | stop | restart
tailwake status [--check]    is it running, the page address, each device's status
tailwake wake [NAME]         wake a device (name not needed if you have one)
tailwake scan                list devices on this network with their MAC addresses
tailwake add NAME MAC [--ip IP] [--broadcast ADDR]
tailwake remove NAME | devices
tailwake config [--port N] [--access tailscale|network] [--password] [--no-password]
tailwake autostart on|off|status [--service]
tailwake tailscale [status|serve-on|serve-off]
tailwake run [--no-tray]     run in the foreground (what start at login uses)
```

Settings and the log live in `%APPDATA%\TailWake\` (Windows), `~/Library/Application Support/TailWake/` (macOS) or
`~/.config/tailwake/` (Linux).

### Without a desktop (Raspberry Pi, home server)

TailWake runs without a tray icon when there is no desktop. Add devices with `tailwake scan` and `tailwake add`, then
`tailwake autostart on` installs a systemd user service. To have it start at boot without logging in, run once:
`sudo loginctl enable-linger $USER`.

## Notes

- **Who can open the page.** By default only Tailscale addresses (100.64.0.0/10) and this computer are answered.
  "Tailscale devices and anyone on this local network" also lets in private LAN addresses. A password adds a login
  on top. Tailscale ACLs still apply: devices your tailnet policy blocks can't reach the page at all.
- **HTTPS address.** "Turn HTTPS address on" runs `tailscale serve`, which gives the page a
  `https://<name>.<tailnet>.ts.net/` address, still visible only inside your tailnet. Your tailnet needs HTTPS
  certificates turned on (admin console → DNS). On Linux, allow your user once with
  `sudo tailscale set --operator=$USER`.
- **Online / offline.** TailWake pings the device, tries a few common ports, and checks this computer's address table
  for the device's MAC address, so a PC that blocks ping still shows as online. Right after a device turns off, it can
  take a minute or two to show as offline (on macOS up to 20 minutes, if it also blocks ping).
- **Status checks only run while someone is looking** (the page is open, or a device was just woken). Regular pings
  can wake some sleeping PCs that use "wake on pattern match", so background checks are off unless you turn them on.
- **Firewall.** The first time, Windows may ask whether Python can use the network: allow Private networks. Other
  firewalls must allow TCP port 8002 (or the port you choose) from your Tailscale interface.
- **Tray icon on Linux.** KDE, Cinnamon, XFCE and most others show it. GNOME needs the "AppIndicator and KStatusNotifierItem
  Support" extension. If the icon is missing, TailWake keeps running: use `tailwake settings` and `tailwake stop`.
- **The magic packet** goes to 255.255.255.255, the local /24 broadcast and the device's last IP address, on UDP ports
  9 and 7. If your network is not a /24, set the device's broadcast address in its settings.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
