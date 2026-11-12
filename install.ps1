# TailWake installer for Windows (PowerShell). No admin rights needed.
#
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/onetrickpony1/TailWake/main/install.ps1 | iex"
#
# It checks what is missing and asks before installing anything:
#   1. Python 3.9+ (needed)   2. the tray icon packages, privately in TailWake's own folder (recommended)
# then saves tailwake.pyw to %LOCALAPPDATA%\TailWake, adds a `tailwake` command and a Start menu shortcut, and offers
# start at login. Run it again to update.
# Uninstall: `tailwake autostart off`, `tailwake stop`, then delete that folder and the Start menu shortcut.
$ErrorActionPreference = "Stop"

$Url = if ($env:TAILWAKE_URL) { $env:TAILWAKE_URL } else { "https://raw.githubusercontent.com/onetrickpony1/TailWake/main/tailwake.py" }
$Dir = Join-Path $env:LOCALAPPDATA "TailWake"

function Say($m) { Write-Host "`n==> $m" }
function Ask($q, $default) {
    if ($env:CI) { return ($default -eq "y") }
    $a = Read-Host "$q"
    if (-not $a) { $a = $default }
    return ($a -match "^[Yy]")
}
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}
function Try-Py($exe, [string[]]$pyargs) {   # run Python quietly; true if it exited 0 (stderr is not an error here)
    $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & $exe @pyargs *> $null; return ($LASTEXITCODE -eq 0) } finally { $ErrorActionPreference = $old }
}
function Find-Python {
    foreach ($c in @("py", "python")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd -and ($cmd.Source -notmatch "WindowsApps")) {
            if (Try-Py $cmd.Source @("-c", "import sys, tkinter; sys.exit(sys.version_info < (3, 9))")) { return $cmd.Source }
        }
    }
    return $null
}

Say "Installing TailWake"

# 1. Python (needed)
$py = Find-Python
if (-not $py) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Python 3.9+ is required. Install it from https://www.python.org/downloads/ and run this again."
    }
    if (-not (Ask "Python 3 is missing and TailWake needs it. Install it now with winget? [Y/n]" "y")) { throw "Python 3 is required" }
    winget install --id Python.Python.3.13 -e --scope user --accept-package-agreements --accept-source-agreements
    Refresh-Path
    $py = Find-Python
    if (-not $py) { throw "Python was installed but can't be found yet; open a new PowerShell window and run this again." }
}

# 2. TailWake's own Python environment
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$venvPy = Join-Path $Dir "venv\Scripts\python.exe"
$venvPyw = Join-Path $Dir "venv\Scripts\pythonw.exe"
$target = Join-Path $Dir "tailwake.pyw"
if (Test-Path $target) { Try-Py $venvPy @($target, "stop") | Out-Null }
if (-not (Test-Path $venvPy)) {
    Say "Creating TailWake's private Python environment"
    if (-not (Try-Py $py @("-m", "venv", (Join-Path $Dir "venv")))) { throw "could not create the Python environment" }
}
if (-not (Try-Py $venvPy @("-c", "import pystray, PIL"))) {
    if (Ask "Install the tray icon packages (pystray, Pillow) into TailWake's own folder? Recommended. [Y/n]" "y") {
        if (-not (Try-Py $venvPy @("-m", "pip", "install", "--quiet", "--disable-pip-version-check", "pystray", "Pillow"))) {
            Write-Host "Could not install them; TailWake still works, just without a tray icon."
        }
    }
}

# 3. the app
Say "Downloading tailwake.py"
if ($env:TAILWAKE_SOURCE -and (Test-Path $env:TAILWAKE_SOURCE)) { Copy-Item $env:TAILWAKE_SOURCE $target -Force }
else { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $target }
if (-not (Try-Py $venvPy @("-m", "py_compile", $target))) { throw "the downloaded file is not valid Python" }

# 4. `tailwake` command
Set-Content -Path (Join-Path $Dir "tailwake.cmd") -Encoding ASCII -Value "@`"%~dp0venv\Scripts\python.exe`" `"%~dp0tailwake.pyw`" %*"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath) { $userPath = "" }
if (($userPath -split ";") -notcontains $Dir) {
    if (Ask "Add the 'tailwake' command to your PATH? [Y/n]" "y") {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $Dir).TrimStart(";"), "User")
    }
}

# 5. Start menu shortcut
if (-not $env:CI -and (Ask "Add TailWake to the Start menu? [Y/n]" "y")) {
    $lnk = Join-Path ([Environment]::GetFolderPath("Programs")) "TailWake.lnk"
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $s.TargetPath = $venvPyw
    $s.Arguments = "`"$target`""
    $s.WorkingDirectory = $Dir
    $s.Description = "Wake your computers over Tailscale"
    $s.Save()
}

# 6. Tailscale
$ts = Join-Path $env:ProgramFiles "Tailscale\tailscale.exe"
if (-not (Test-Path $ts) -and -not (Get-Command tailscale -ErrorAction SilentlyContinue)) {
    Write-Host "`nNote: Tailscale was not found. Install it on this PC AND your phone: https://tailscale.com/download"
}

# 7. start at login, start now
if (-not $env:CI) {
    if (Ask "Start TailWake automatically when you sign in? [Y/n]" "y") { & $venvPy $target autostart on }
    if (Ask "Start TailWake now? [Y/n]" "y") { Start-Process -FilePath $venvPyw -ArgumentList "`"$target`"" -WorkingDirectory $Dir }
}

Say "Done. Start it from the Start menu, or run 'tailwake' in a NEW terminal. Settings: tailwake settings"
Write-Host "Windows may ask whether Python can use the network the first time: allow Private networks."
