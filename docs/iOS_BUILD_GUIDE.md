# iOS App Build Guide

This guide explains how to build the SentinelPass iOS app from source.

## Prerequisites

- macOS 14.0+ (Sonoma or later)
- Xcode 15.0+
- Rust toolchain (stable)
- iOS Device or Simulator (iOS 17.0+)

## Step 1: Build the Rust Mobile Bridge

First, build the mobile bridge static library that the iOS app will link against:

```bash
cd /path/to/sentinelpass
cargo build --package sentinelpass-mobile-bridge --release
```

This produces:
- Static library: `target/release/libsentinelpass_mobile_bridge.a`
- C header: `sentinelpass-mobile-bridge/include/sentinelpass_bridge.h`

## Step 2: Set Up Xcode Project

### Option A: Create New Xcode Project

If you haven't created an Xcode project yet:

1. **Create a new iOS App project**:
   - Open Xcode
   - File → New → Project
   - Select "iOS" → "App"
   - Product Name: `SentinelPass`
   - Interface: `SwiftUI`
   - Language: `Swift`
   - Storage: `SwiftData`
   - Save to: `ios/SentinelPass/`

2. **Add the Rust library**:

   - In Xcode, select the project in the navigator
   - Select your app target
   - Go to "Build Phases" → "Link Binary With Libraries"
   - Click "+" → "Add Other..." → navigate to `target/release/libsentinelpass_mobile_bridge.a`

3. **Add the header search path**:

   - Go to "Build Settings" → "Header Search Paths"
   - Add: `$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include` (recursive)

4. **Link required frameworks**:

   - "Build Phases" → "Link Binary With Libraries"
   - Add: `LocalAuthentication.framework`, `SwiftData.framework`

5. **Copy the Swift files**:

   - Copy all `.swift` files from `ios/SentinelPass/SentinelPass/` to your Xcode project
   - Copy `ios/SentinelPass/SentinelPassBridge/VaultBridge.swift` to your Xcode project
   - Use "Create groups" when prompted

### Option B: Use Existing Project Structure

If you already have the project files from `ios/SentinelPass/`:

1. Open `ios/SentinelPass/SentinelPass.xcodeproj` in Xcode
2. The project should already have the correct structure

## Step 3: Configure Signing & Capabilities

1. **Select your development team**:
   - Project settings → Signing & Capabilities
   - Select your team (requires Apple Developer account for device testing)

2. **Add capabilities**:
   - "+ Capability" → "Face ID" (for biometric unlock)

## Step 4: Build and Run

### Simulator Build

```bash
# From command line
xcodebuild -project ios/SentinelPass/SentinelPass.xcodeproj \
           -scheme SentinelPass \
           -destination 'platform=iOS Simulator,name=iPhone 15' \
           clean build
```

Or in Xcode:
1. Select a simulator from the device menu (e.g., iPhone 15)
2. Press `Cmd+R` or click the Play button

### Device Build

```bash
# From command line
xcodebuild -project ios/SentinelPass/SentinelPass.xcodeproj \
           -scheme SentinelPass \
           -destination 'generic/platform=iOS' \
           -configuration Release \
           clean build
```

Or in Xcode:
1. Connect your iOS device
2. Select your device from the device menu
3. Press `Cmd+R` or click the Play button

## Architecture Considerations

The iOS app is built as a **universal binary** supporting both architectures:

### Simulator
- **arm64** (Apple Silicon Macs)
- **x86_64** (Intel Macs - Rosetta)

### Device
- **arm64** (iPhone 6s+, all iPad Pro/Air/mini)

### Building for Multiple Architectures

To build a universal library:

```bash
# Build for arm64 (device/Apple Silicon)
cargo build --package sentinelpass-mobile-bridge --release --target aarch64-apple-ios

# Build for x86_64 (Intel simulator)
cargo build --package sentinelpass-mobile-bridge --release --target x86_64-apple-ios

# Combine using lipo
lipo -create \
  target/aarch64-apple-ios/release/libsentinelpass_mobile_bridge.a \
  target/x86_64-apple-ios/release/libsentinelpass_mobile_bridge.a \
  -output target/universal/libsentinelpass_mobile_bridge.a
```

Then link the universal library in Xcode.

## Troubleshooting

### "Undefined symbols for architecture arm64"

This means the static library isn't being linked properly:

1. Verify the library path in "Link Binary With Libraries"
2. Check that you built the library for the correct architecture
3. Ensure the header search path includes the `include/` directory

### "sentinelpass_bridge.h file not found"

The header search path is incorrect:

1. Add `$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include` to "Header Search Paths"
2. Make sure it's set to "recursive" (✓)

### "Cannot find 'VaultBridge' in scope"

The Swift bridge file isn't included in the target:

1. Select `VaultBridge.swift` in Xcode
2. In File Inspector, verify "Target Membership" includes your app

### Build fails on device but works on simulator

Architecture mismatch - you need to build for arm64-ios:

```bash
cargo build --package sentinelpass-mobile-bridge --release --target aarch64-apple-ios
```

### Face ID not working

1. Verify `NSFaceIDUsageDescription` is in `Info.plist`
2. Check that "Face ID" capability is added in Xcode
3. Test on physical device (simulator has limited biometric support)

## Running Tests

The iOS app includes XCTest unit tests:

```bash
xcodebuild test -project ios/SentinelPass/SentinelPass.xcodeproj \
               -scheme SentinelPass \
               -destination 'platform=iOS Simulator,name=iPhone 15'
```

## App Store Distribution

When ready for App Store submission:

1. **Update version numbers**:
   - Project settings → General → Version
   - Project settings → General → Build

2. **Create archive**:
   - Product → Archive
   - Wait for build to complete

3. **Validate and distribute**:
   - Window → Organizer
   - Select your archive
   - "Validate App" → fix any issues
   - "Distribute App" → follow prompts

### Required App Store Info

- **Bundle Identifier**: `com.sentinelpass.ios` (or your own)
- **Category**: Productivity → Utilities
- **Privacy**: Local network, Face ID usage
- **Age Rating**: 4+ (no offensive content)

## Continuous Integration

### GitHub Actions Example

```yaml
name: iOS Build

on: [push, pull_request]

jobs:
  build:
    runs-on: macos-latest

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true

    - name: Build mobile bridge
      run: |
        cargo build --package sentinelpass-mobile-bridge --release

    - name: Build iOS app
      run: |
        xcodebuild -project ios/SentinelPass/SentinelPass.xcodeproj \
                   -scheme SentinelPass \
                   -destination 'platform=iOS Simulator,name=iPhone 15' \
                   clean build
```

## Next Steps

After building:

1. Test the app in simulator
2. Test on physical device
3. Verify biometric authentication
4. Test password CRUD operations
5. Test TOTP generation
6. Test password generator

For app usage guide, see `ios/SentinelPass/README.md`.
