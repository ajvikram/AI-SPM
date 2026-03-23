#!/bin/bash
# ============================================================
#  AI-SPM — Build & Package Script
#  Creates release binaries and platform-specific packages.
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

echo "🛡️  AI-SPM Build Script"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Build release binaries ───────────────────────────────
echo "📦  Building release binaries..."
cd "$ROOT"
cargo build --release

# ── 2. macOS .app bundle ────────────────────────────────────
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎  Packaging macOS .app bundle..."
    APP="$DIST/macos/AI-SPM.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

    # Copy binaries
    cp target/release/ai-spm-monitor "$APP/Contents/MacOS/"
    cp target/release/ai-spm         "$APP/Contents/MacOS/"

    # Copy UI
    cp ui/index.html "$APP/Contents/Resources/"

    # Generate .icns from PNG icon
    ICONSET="/tmp/ai-spm-icon.iconset"
    rm -rf "$ICONSET" && mkdir -p "$ICONSET"
    ICON_SRC="crates/ai-spm-monitor/assets/icon.png"

    sips -z 16   16   "$ICON_SRC" --out "$ICONSET/icon_16x16.png"      >/dev/null
    sips -z 32   32   "$ICON_SRC" --out "$ICONSET/icon_16x16@2x.png"   >/dev/null
    sips -z 32   32   "$ICON_SRC" --out "$ICONSET/icon_32x32.png"      >/dev/null
    sips -z 64   64   "$ICON_SRC" --out "$ICONSET/icon_32x32@2x.png"   >/dev/null
    sips -z 128  128  "$ICON_SRC" --out "$ICONSET/icon_128x128.png"    >/dev/null
    sips -z 256  256  "$ICON_SRC" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
    sips -z 256  256  "$ICON_SRC" --out "$ICONSET/icon_256x256.png"    >/dev/null
    sips -z 512  512  "$ICON_SRC" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
    sips -z 512  512  "$ICON_SRC" --out "$ICONSET/icon_512x512.png"    >/dev/null
    cp "$ICON_SRC" "$ICONSET/icon_512x512@2x.png"

    iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
    rm -rf "$ICONSET"

    # Info.plist
    cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key><string>AI-SPM</string>
    <key>CFBundleExecutable</key><string>ai-spm-monitor</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>com.aispm.monitor</string>
    <key>CFBundleName</key><string>AI-SPM</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key><true/>
</dict>
</plist>
PLIST

    echo "   ✅ AI-SPM.app → $APP"

    # Create DMG-like zip for easy distribution
    echo "📦  Creating distributable archive..."
    cd "$DIST/macos"
    zip -r "$DIST/AI-SPM-macOS-arm64.zip" AI-SPM.app >/dev/null
    cd "$ROOT"
    echo "   ✅ AI-SPM-macOS-arm64.zip → $DIST/"
fi

# ── 3. Summary ──────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦  Build complete!"
echo ""
ls -lh "$DIST/"*.zip 2>/dev/null || true
echo ""
echo "macOS:   dist/macos/AI-SPM.app  (double-click to run)"
echo "CLI:     target/release/ai-spm   (copy to /usr/local/bin/)"
echo ""
echo "Windows: Cross-compile with:"
echo "   cargo build --release --target x86_64-pc-windows-gnu"
echo "   (requires: brew install mingw-w64)"
echo ""
