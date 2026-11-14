# TailWake installer for Windows (PowerShell). No admin rights needed.
#
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/onetrickpony1/tailwake/main/install.ps1 | iex"
#
# It checks what is missing and asks before installing anything:
#   1. Python 3.10+ (needed)   2. the tray icon packages, privately in TailWake's own folder (recommended)
# then downloads and checks tailwake.py, saves it as tailwake.pyw in %LOCALAPPDATA%\TailWake, adds a `tailwake`
# command and a Start menu shortcut, and offers start at login. Run it again to update.
# Uninstall: `tailwake autostart off`, `tailwake stop`, then delete that folder and the Start menu shortcut.
$ErrorActionPreference = "Stop"

$Url = if ($env:TAILWAKE_URL) { $env:TAILWAKE_URL } else { "https://raw.githubusercontent.com/onetrickpony1/tailwake/main/tailwake.py" }
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
            if (Try-Py $cmd.Source @("-c", "import sys, tkinter; sys.exit(sys.version_info < (3, 10))")) { return $cmd.Source }
        }
    }
    return $null
}

Say "Installing TailWake"

# 1. Python (needed)
$py = Find-Python
if (-not $py) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Python 3.10+ is required. Install it from https://www.python.org/downloads/ and run this again."
    }
    if (-not (Ask "Python 3 is missing and TailWake needs it. Install it now with winget? [Y/n]" "y")) { throw "Python 3 is required" }
    winget install --id Python.Python.3.13 -e --scope user --accept-package-agreements --accept-source-agreements
    Refresh-Path
    $py = Find-Python
    if (-not $py) { throw "Python was installed but can't be found yet; open a new PowerShell window and run this again." }
}

# 2. download the app first: if that fails, the installed TailWake is left as it was (and keeps running)
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$venvPy = Join-Path $Dir "venv\Scripts\python.exe"
$venvPyw = Join-Path $Dir "venv\Scripts\pythonw.exe"
$target = Join-Path $Dir "tailwake.pyw"
$new = "$target.new"
Say "Downloading tailwake.py"
try {
    if ($env:TAILWAKE_SOURCE -and (Test-Path $env:TAILWAKE_SOURCE)) { Copy-Item $env:TAILWAKE_SOURCE $new -Force }
    else { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $new }
} catch {
    Remove-Item $new -Force -ErrorAction SilentlyContinue
    throw "the download failed; your existing TailWake was left as it was ($_)"
}
if (-not (Try-Py $py @("-c", "import sys; compile(open(sys.argv[1], 'rb').read(), 'tailwake.py', 'exec')", $new))) {
    Remove-Item $new -Force -ErrorAction SilentlyContinue
    throw "the downloaded file is not valid Python; your existing TailWake was left as it was"
}

# 3. TailWake's own Python environment
if (Test-Path $target) { Try-Py $venvPy @($target, "stop") | Out-Null }
if (-not (Test-Path $venvPy)) {
    Say "Creating TailWake's private Python environment"
    if (-not (Try-Py $py @("-m", "venv", (Join-Path $Dir "venv")))) { throw "could not create the Python environment" }
}
if (-not (Try-Py $venvPy @("-c", "import importlib.util as u, PIL, sys; sys.exit(not u.find_spec('pystray'))"))) {
    if (Ask "Install the tray icon packages (pystray, Pillow) into TailWake's own folder? Recommended. [Y/n]" "y") {
        if (-not (Try-Py $venvPy @("-m", "pip", "install", "--quiet", "--disable-pip-version-check", "pystray", "Pillow"))) {
            Write-Host "Could not install them; TailWake still works, just without a tray icon."
        }
    }
}

# 4. the app: put the checked download in place
Move-Item -Path $new -Destination $target -Force

# 5. `tailwake` command
Set-Content -Path (Join-Path $Dir "tailwake.cmd") -Encoding ASCII -Value "@`"%~dp0venv\Scripts\python.exe`" `"%~dp0tailwake.pyw`" %*"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath) { $userPath = "" }
if (($userPath -split ";") -notcontains $Dir) {
    if (Ask "Add the 'tailwake' command to your PATH? [Y/n]" "y") {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $Dir).TrimStart(";"), "User")
    }
}

# 6. Start menu shortcut
if (-not $env:CI -and (Ask "Add TailWake to the Start menu? [Y/n]" "y")) {
    $lnk = Join-Path ([Environment]::GetFolderPath("Programs")) "TailWake.lnk"
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $s.TargetPath = $venvPyw
    $s.Arguments = "`"$target`""
    $s.WorkingDirectory = $Dir
    $s.Description = "Wake your computers over Tailscale"
    $s.Save()
}

# 7. Tailscale
$ts = Join-Path $env:ProgramFiles "Tailscale\tailscale.exe"
if (-not (Test-Path $ts) -and -not (Get-Command tailscale -ErrorAction SilentlyContinue)) {
    Write-Host "`nNote: Tailscale was not found. Install it on this PC AND your phone: https://tailscale.com/download"
}

# 8. start at login, start now
if (-not $env:CI) {
    if (Ask "Start TailWake automatically when you sign in? [Y/n]" "y") { & $venvPy $target autostart on }
    if (Ask "Start TailWake now? [Y/n]" "y") { Start-Process -FilePath $venvPyw -ArgumentList "`"$target`"" -WorkingDirectory $Dir }
}

Say "Done. Start it from the Start menu, or run 'tailwake' in a NEW terminal. Settings: tailwake settings"
Write-Host "Windows may ask whether Python can use the network the first time: allow Private networks."
