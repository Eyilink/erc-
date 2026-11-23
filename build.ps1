<#
.SYNOPSIS
    Build erc++ for x86 and/or x64.

.PARAMETER Platform
    x86 | x64 | both (default: both)

.PARAMETER X64dbgRoot
    Path to your x64dbg installation (must contain x32\ and x64\ subdirectories).
    Default: C:\x64dbg

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Platform x64
    .\build.ps1 -Platform x86 -X64dbgRoot "D:\Tools\x64dbg"
#>
param(
    [ValidateSet("x86","x64","both")]
    [string]$Platform = "both",
    [string]$X64dbgRoot = "C:\x64dbg"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── locate MSBuild / cl.exe via vswhere ──────────────────────────────────────
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere not found. Install Visual Studio 2022 (or Build Tools)."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 `
                     -property installationPath
if (-not $vsPath) {
    Write-Error "No Visual Studio installation with C++ tools found."
}

# vcvarsall.bat path
$vcvarsall = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) {
    Write-Error "vcvarsall.bat not found at: $vcvarsall"
}

$src     = "$PSScriptRoot\erc_plus.cpp"
$def     = "$PSScriptRoot\erc_plus.def"
$sdkBase = "$PSScriptRoot\pluginsdk"

function Build-Plugin {
    param([string]$arch)   # "x86" or "x64"

    $vcArch   = if ($arch -eq "x64") { "x64" }   else { "x86" }
    $libDir   = if ($arch -eq "x64") { "x64" }   else { "x32" }
    $dbgLib   = if ($arch -eq "x64") { "x64dbg.lib" } else { "x32dbg.lib" }
    $bridgeLib= if ($arch -eq "x64") { "x64bridge.lib" } else { "x32bridge.lib" }
    $ext      = if ($arch -eq "x64") { "dp64" }  else { "dp32" }
    $out      = "$PSScriptRoot\erc_plus.$ext"
    $plugDir  = "$X64dbgRoot\$libDir\plugins"
    $sdkLib   = "$sdkBase\$libDir"

    Write-Host ""
    Write-Host "=== Building $arch ===" -ForegroundColor Cyan

    # Verify SDK libs exist
    foreach ($lib in @("$sdkLib\$dbgLib", "$sdkLib\$bridgeLib")) {
        if (-not (Test-Path $lib)) {
            Write-Error "SDK lib not found: $lib`nMake sure pluginsdk\ is next to build.ps1 (see README)."
        }
    }

    # Build the cl.exe command as a single line (no backtick line-continuation
    # inside the bat file – cmd.exe does not understand PowerShell backticks).
    $clArgs = "/EHsc /W3 /O2 /LD /DWIN32 /D_WINDOWS /D_USRDLL /DUNICODE /D_UNICODE /I`"$sdkBase`" `"$src`" /Fe:`"$out`" /link /DEF:`"$def`" `"$sdkLib\$dbgLib`" `"$sdkLib\$bridgeLib`" psapi.lib"

    $clCmd = "call `"$vcvarsall`" $vcArch" + [Environment]::NewLine + "cl $clArgs"

    $tmp = [System.IO.Path]::GetTempFileName() + ".bat"
    Set-Content -Path $tmp -Value $clCmd -Encoding ASCII
    & cmd /c $tmp
    Remove-Item $tmp -ErrorAction SilentlyContinue

    if (-not (Test-Path $out)) {
        Write-Error "Build failed for $arch - output not found: $out"
    }

    # Verify architecture of the produced DLL
    $bytes = [System.IO.File]::ReadAllBytes($out)
    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    $machine  = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $expectMachine = if ($arch -eq "x64") { 0x8664 } else { 0x014C }
    if ($machine -ne $expectMachine) {
        Write-Error "Architecture mismatch in output DLL (machine=0x$($machine.ToString('X4')))."
    }

    Write-Host "Built: $out" -ForegroundColor Green

    # Copy to x64dbg plugins directory if it exists
    if (Test-Path $plugDir) {
        Copy-Item $out $plugDir -Force
        Write-Host "Installed to: $plugDir" -ForegroundColor Green
    } else {
        Write-Host "Plugin dir not found ($plugDir) - copy manually." -ForegroundColor Yellow
    }
}

if ($Platform -eq "both" -or $Platform -eq "x86") { Build-Plugin "x86" }
if ($Platform -eq "both" -or $Platform -eq "x64") { Build-Plugin "x64" }

Write-Host ""
Write-Host "Done. Restart x64dbg to load the plugin." -ForegroundColor Cyan
