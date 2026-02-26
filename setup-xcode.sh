#!/bin/bash
# iOS Simulator Setup Script
# This script helps prepare the iOS app for Xcode

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=== SentinelPass iOS Setup ==="
echo ""

# 1. Build the mobile bridge for iOS (x86_64 for Intel Mac simulators, arm64 for Apple Silicon)
echo "1. Building mobile bridge for iOS simulators..."

# Detect if we're on Apple Silicon or Intel
if [[ "$(uname -m)" == "arm64" ]]; then
    echo "   Building for arm64 (Apple Silicon)..."
    cargo build --package sentinelpass-mobile-bridge --release
    BRIDGE_LIB="target/release/libsentinelpass_mobile_bridge.a"
else
    echo "   Building for x86_64 (Intel)..."
    cargo build --package sentinelpass-mobile-bridge --release --target x86_64-apple-ios
    BRIDGE_LIB="target/x86_64-apple-ios/release/libsentinelpass_mobile_bridge.a"
fi

if [ ! -f "$BRIDGE_LIB" ]; then
    echo "ERROR: Bridge library not found at $BRIDGE_LIB"
    exit 1
fi

echo "   ✓ Built: $BRIDGE_LIB"
echo ""

# 2. Show library and header locations
echo "2. Bridge files ready:"
echo "   Static library: $BRIDGE_LIB"
echo "   C header: sentinelpass-mobile-bridge/include/sentinelpass_bridge.h"
echo ""

# 3. Check Xcode
echo "3. Checking Xcode..."
if command -v xcodebuild &> /dev/null; then
    XCODE_VERSION=$(xcodebuild -version | head -1)
    echo "   ✓ Xcode found: $XCODE_VERSION"
else
    echo "   ✗ Xcode not found. Install from App Store."
    exit 1
fi
echo ""

# 4. Create a simple launcher that opens Xcode with a new project
echo "4. To create an Xcode project:"
echo ""
echo "   OPTION A: Manual Setup (Recommended)"
echo "   -----------------------------------"
echo "   a) Open Xcode"
echo "   b) File → New → Project"
echo "   c) Select 'iOS' → 'App'"
echo "   d) Configure:"
echo "      - Product Name: SentinelPass"
echo "      - Team: (Your Apple ID)"
echo "      - Organization Identifier: com.sentinelpass"
echo "      - Interface: SwiftUI"
echo "      - Language: Swift"
echo "      - Storage: SwiftData"
echo "      - Save to: $(pwd)/SentinelPass (replace existing)"
echo ""
echo "   e) After creating project:"
echo "      1. Delete auto-generated SentinelPassApp.swift and ContentView.swift"
echo "      2. Copy all .swift files from ios/SentinelPass/SentinelPass/ to project"
echo "      3. Copy SentinelPassBridge/ folder to project"
echo "      4. Add static library: Build Phases → Link Binary With Libraries → Add Other..."
echo "         Navigate to: $BRIDGE_LIB"
echo "      5. Add header search path: Build Settings → Header Search Paths"
echo "         Add: $(pwd)/../sentinelpass-mobile-bridge/include (recursive ✓)"
echo "      6. Add LocalAuthentication framework"
echo "      7. Add Face ID capability"
echo ""
echo "   OPTION B: Quick Test with Command Line"
echo "   ---------------------------------------"
echo "   Use xcodebuild to build once project is set up:"
echo ""
echo "   xcodebuild -project ios/SentinelPass/SentinelPass.xcodeproj \\"
echo "              -scheme SentinelPass \\"
echo "              -destination 'platform=iOS Simulator,name=iPhone 15' \\"
echo "              build"
echo ""

# 5. List available simulators
echo "5. Available iOS Simulators:"
xcrun simctl list devices available | grep -E "iPhone|iPad" | head -10
echo ""
echo "   Full list: xcrun simctl list devices"
echo ""

echo "=== Setup Complete ==="
echo ""
echo "Next: Open Xcode and create a new project following OPTION A above."
