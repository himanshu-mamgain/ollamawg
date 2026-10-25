# Installs the ollamawg binary from GitHub Releases on Windows.
#
#   irm https://himanshu-mamgain.github.io/ollamawg/install.ps1 | iex
#
# Environment:
#   OLLAMAWG_VERSION          release to install, e.g. 0.4.0 (default: latest)
#   OLLAMAWG_INSTALL_DIR      where to put ollamawg.exe
#                             (default: %LOCALAPPDATA%\Programs\ollamawg)
#   OLLAMAWG_NO_MODIFY_PATH   set to 1 to leave your PATH alone
# No admin rights needed. Works in Windows PowerShell 5.1 and PowerShell 7.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is far slower with the progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'himanshu-mamgain/ollamawg'
$asset = 'ollamawg-windows-amd64.exe'   # also runs on Windows on Arm, through emulation
if ($env:OLLAMAWG_VERSION) {
    $base = "https://github.com/$repo/releases/download/v$($env:OLLAMAWG_VERSION.TrimStart('v'))"
} else {
    $base = "https://github.com/$repo/releases/latest/download"
}

$dir = $env:OLLAMAWG_INSTALL_DIR
if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\ollamawg' }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# Resolve to a full long path; short 8.3 names like C:\Users\HPPC~1 confuse some cmdlets.
$dir = (Get-Item -LiteralPath $dir).FullName
$tmp = Join-Path $dir 'ollamawg.download'
$exe = Join-Path $dir 'ollamawg.exe'

try {
    Write-Host "Downloading $asset ..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $tmp

    # Verify against the release's SHA256SUMS (published from 0.4.1 on; older releases skip this).
    $sums = $null
    try { $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content } catch { }
    if ($sums) {
        if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }
        $line = ($sums -split "`n") | Where-Object { $_ -match "^([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($asset))\s*$" } | Select-Object -First 1
        if (-not $line) { throw "SHA256SUMS has no entry for $asset" }
        $want = ($line -split '\s+')[0].ToLower()
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLower()
        if ($got -ne $want) { throw "checksum mismatch for $asset (expected $want, got $got)" }
        Write-Host 'Checksum OK.'
    } else {
        Write-Host 'This release has no SHA256SUMS; skipping checksum verification.'
    }

    Move-Item -Force -LiteralPath $tmp -Destination $exe
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -Force -LiteralPath $tmp }
}

$version = & $exe version
Write-Host "Installed ollamawg $version to $exe"

if ($env:OLLAMAWG_NO_MODIFY_PATH -ne '1') {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($userPath) { $parts = $userPath -split ';' | Where-Object { $_ } }
    if ($parts -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User')
        Write-Host "Added $dir to your user PATH. Open a new terminal to use 'ollamawg'."
    }
    if (($env:Path -split ';') -notcontains $dir) { $env:Path = "$env:Path;$dir" }
}
Write-Host 'Next: ollamawg init --endpoint <your-public-ip-or-dns>:51820   (see https://himanshu-mamgain.github.io/ollamawg/)'
