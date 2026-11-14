#!/bin/sh
# TailWake installer for Linux and macOS. No admin rights needed (only to install missing system packages).
#
#   curl -LsSf https://raw.githubusercontent.com/onetrickpony1/tailwake/main/install.sh | sh
#
# It checks what is missing and asks before installing anything:
#   1. Python 3.10+ with tkinter (needed)   2. the tray icon packages, privately in TailWake's own folder (recommended)
# then downloads and checks tailwake.py, saves it to ~/.local/share/tailwake, adds a `tailwake` command, a menu entry
# (Linux) or ~/Applications/TailWake.app (macOS), and offers start at login.
# Run it again to update. Uninstall: `tailwake autostart off`, `tailwake stop`, then delete ~/.local/share/tailwake,
# ~/.local/bin/tailwake and the menu entry / app.
set -eu

URL="${TAILWAKE_URL:-https://raw.githubusercontent.com/onetrickpony1/tailwake/main/tailwake.py}"
DIR="$HOME/.local/share/tailwake"
BIN="$HOME/.local/bin"
OS="$(uname)"

say() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nTailWake installer: %s\n' "$*" >&2; exit 1; }
ask() {   # ask "question" default(y/n) -> 0 for yes; no terminal or CI -> default
    if [ -z "${CI:-}" ] && ( : < /dev/tty ) 2>/dev/null; then
        printf '%s ' "$1" > /dev/tty
        read -r ans < /dev/tty || ans=""
    else
        ans=""
    fi
    [ -z "$ans" ] && ans="$2"
    case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}
py_ok() { python3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >/dev/null 2>&1; }
have_tk() { python3 -c "import tkinter" >/dev/null 2>&1; }

# Run a package-manager command, with sudo if we are not root.
pm() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

# install_pkg "what" "apt names" "dnf names" "pacman names" "brew names"
install_pkg() {
    if command -v apt-get >/dev/null 2>&1; then pm apt-get install -y $2
    elif command -v dnf >/dev/null 2>&1; then pm dnf install -y $3
    elif command -v pacman >/dev/null 2>&1; then pm pacman -S --needed --noconfirm $4
    elif command -v zypper >/dev/null 2>&1; then pm zypper install -y $3
    elif command -v brew >/dev/null 2>&1; then brew install $5
    else printf "Don't know your package manager; please install %s yourself.\n" "$1"; return 1
    fi
}

say "Installing TailWake"

# 1. Python 3.10+ with tkinter (needed)
if ! command -v python3 >/dev/null 2>&1 || ! py_ok; then
    ask "Python 3.10 or newer is missing and TailWake needs it. Install it now (may ask for your password)? [Y/n]" y \
        || fail "Python 3.10+ is required"
    install_pkg "Python 3" python3 python3 python python@3.13 || fail "could not install Python 3"
    py_ok || fail "Python 3.10+ still isn't available; please install it and run this again"
fi
if ! have_tk; then
    ask "Python's tkinter (needed for the settings window) is missing. Install it now? [Y/n]" y \
        || fail "tkinter is required for the settings window"
    install_pkg "tkinter for Python" python3-tk python3-tkinter tk python-tk || fail "could not install tkinter"
    have_tk || fail "tkinter still can't be imported; please install it for your Python and run this again"
fi

# 2. download the app first: if that fails, the installed TailWake is left as it was (and keeps running)
mkdir -p "$DIR" "$BIN"
NEW="$DIR/tailwake.py.new"
say "Downloading tailwake.py"
if [ -f "${TAILWAKE_SOURCE:-}" ]; then cp "$TAILWAKE_SOURCE" "$NEW"
elif command -v curl >/dev/null 2>&1; then curl -LsSf "$URL" -o "$NEW" || { rm -f "$NEW"; fail "the download failed; your existing TailWake was left as it was"; }
elif command -v wget >/dev/null 2>&1; then wget -qO "$NEW" "$URL" || { rm -f "$NEW"; fail "the download failed; your existing TailWake was left as it was"; }
else fail "needs curl or wget to download the app"
fi
if ! python3 -c "import sys; compile(open(sys.argv[1], 'rb').read(), 'tailwake.py', 'exec')" "$NEW" >/dev/null 2>&1; then
    rm -f "$NEW"
    fail "the downloaded file is not valid Python; your existing TailWake was left as it was"
fi

# 3. TailWake's own Python environment (keeps the tray packages away from your system Python)
"$BIN/tailwake" stop >/dev/null 2>&1 || true
if [ ! -x "$DIR/venv/bin/python" ]; then
    say "Creating TailWake's private Python environment"
    if ! python3 -m venv --system-site-packages "$DIR/venv" >/dev/null 2>&1; then
        rm -rf "$DIR/venv"
        ask "Python's venv module is missing. Install it now? [Y/n]" y || fail "the venv module is required"
        install_pkg "Python venv" python3-venv python3 python python@3.13 || fail "could not install python3-venv"
        python3 -m venv --system-site-packages "$DIR/venv" || fail "could not create the environment"
    fi
fi
PY="$DIR/venv/bin/python"

if ! "$PY" -c "import importlib.util as u, PIL, sys; sys.exit(not u.find_spec('pystray'))" >/dev/null 2>&1; then
    if ask "Install the tray icon packages (pystray, Pillow) into TailWake's own folder? Recommended. [Y/n]" y; then
        "$PY" -m pip install --quiet --disable-pip-version-check pystray Pillow \
            || printf 'Could not install them; TailWake still works, just without a tray icon.\n'
    fi
fi

if [ "$OS" = "Linux" ] && ! "$PY" -c "import gi" >/dev/null 2>&1; then
    if ask "Optional: install AppIndicator support for a better tray icon on GNOME and KDE? [y/N]" n; then
        install_pkg "AppIndicator support" "python3-gi gir1.2-ayatanaappindicator3-0.1" \
            "python3-gobject libayatana-appindicator-gtk3" "python-gobject libayatana-appindicator" "" \
            || printf 'Skipped; the tray icon falls back to the plain X11 tray.\n'
    fi
fi

# 4. the app: put the checked download in place
mv -f "$NEW" "$DIR/tailwake.py"
printf '#!/bin/sh\nexec "%s" "%s/tailwake.py" "$@"\n' "$PY" "$DIR" > "$BIN/tailwake"
chmod +x "$BIN/tailwake"

# 5. menu entry / app
if [ -z "${CI:-}" ]; then
    if [ "$OS" = "Linux" ] && ask "Add TailWake to your applications menu? [Y/n]" y; then
        mkdir -p "$HOME/.local/share/applications"
        printf '[Desktop Entry]\nType=Application\nName=TailWake\nComment=Wake your computers over Tailscale\nExec=%s/tailwake\nIcon=system-shutdown\nTerminal=false\nCategories=Network;Utility;\n' \
            "$BIN" > "$HOME/.local/share/applications/tailwake.desktop"
    elif [ "$OS" = "Darwin" ] && ask "Add TailWake.app to ~/Applications (for Spotlight and Launchpad)? [Y/n]" y; then
        APPDIR="$HOME/Applications/TailWake.app/Contents"
        mkdir -p "$APPDIR/MacOS"
        printf '#!/bin/sh\nexec "%s/tailwake" "$@"\n' "$BIN" > "$APPDIR/MacOS/TailWake"
        chmod +x "$APPDIR/MacOS/TailWake"
        cat > "$APPDIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>TailWake</string>
<key>CFBundleIdentifier</key><string>io.github.tailwake.launcher</string>
<key>CFBundleExecutable</key><string>TailWake</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
    fi
fi

# 6. Tailscale
if ! command -v tailscale >/dev/null 2>&1 && [ ! -e /Applications/Tailscale.app ]; then
    printf '\nNote: Tailscale was not found. Install it on this computer AND your phone: https://tailscale.com/download\n'
fi

# 7. start at login, start now
if [ -z "${CI:-}" ]; then
    if ask "Start TailWake automatically when you log in? [Y/n]" y; then
        "$BIN/tailwake" autostart on || true
    fi
    if ask "Start TailWake now? [Y/n]" y; then
        "$BIN/tailwake" || true
    fi
fi

say "Done."
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) printf 'Open a NEW terminal so the command is found (it is in %s).\n' "$BIN" ;;
esac
printf '\nStart with:   tailwake            Settings:   tailwake settings\n'
