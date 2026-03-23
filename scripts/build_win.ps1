param(
    [switch]$Help
)

if ($Help) {
    Write-Host "AI-SPM Windows Build Script"
    Write-Host "==========================="
    Write-Host "Ensure you have the Rust x86_64-pc-windows-gnu target installed:"
    Write-Host "rustup target add x86_64-pc-windows-gnu"
    Write-Host "And MinGW-w64 installed: brew install mingw-w64 (on Mac)"
    exit 0
}

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT = (Get-Item -Path (Join-Path $SCRIPT_DIR "..")).FullName
$DIST = Join-Path $ROOT "dist"
Set-Location -Path $ROOT

Write-Host "🛡️  AI-SPM Windows Build Script"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "📦  Building release binaries for Windows (x86_64-pc-windows-gnu)..."

# Build for Windows GNU target
cargo build --release --target x86_64-pc-windows-gnu

Write-Host "🪟  Packaging Windows .exe bundle..."
$APP_DIR = Join-Path $DIST "windows"
if (!(Test-Path $APP_DIR)) {
    New-Item -ItemType Directory -Force -Path $APP_DIR | Out-Null
}

$BIN_PATH = Join-Path $ROOT "target\x86_64-pc-windows-gnu\release\ai-spm-monitor.exe"
$CLI_PATH = Join-Path $ROOT "target\x86_64-pc-windows-gnu\release\ai-spm.exe"

Copy-Item -Force $BIN_PATH -Destination (Join-Path $APP_DIR "AI-SPM.exe")
Copy-Item -Force $CLI_PATH -Destination (Join-Path $APP_DIR "ai-spm.exe")

Write-Host "   ✅ Windows executable → $APP_DIR\AI-SPM.exe"
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "📦  Build complete!"
