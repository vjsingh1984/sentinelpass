#!/bin/bash
# Android Setup Verification Script

set -e

echo "=== Verifying Android Setup ==="
echo ""

# Detect SDK path
if [ -d "$HOME/Library/Android/sdk" ]; then
    SDK_PATH="$HOME/Library/Android/sdk"
elif [ -d "$HOME/Android/Sdk" ]; then
    SDK_PATH="$HOME/Android/Sdk"
else
    echo "❌ Android SDK not found."
    echo ""
    echo "Please complete Android Studio setup first:"
    echo "  1. Open Android Studio"
    echo "  2. Complete the setup wizard (Standard installation)"
    echo "  3. Install NDK via SDK Manager"
    echo ""
    exit 1
fi

echo "✓ Android SDK found: $SDK_PATH"
echo ""

# Detect NDK
NDK_PATH=$(ls -d "$SDK_PATH"/ndk/* 2>/dev/null | sort -V | tail -1)
if [ -z "$NDK_PATH" ]; then
    echo "❌ NDK not found."
    echo ""
    echo "Install NDK:"
    echo "  1. Open Android Studio"
    echo "  2. Tools → SDK Manager"
    echo "  3. SDK Tools tab"
    echo "  4. Check 'NDK (Side by side)'"
    echo "  5. Click Apply"
    echo ""
    exit 1
fi

echo "✓ NDK found: $NDK_PATH"
echo ""

# Set up environment for build
export ANDROID_NDK_HOME="$NDK_PATH"
export PATH="$NDK_PATH/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"

echo "Building JNI libraries..."
echo ""

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Run the build script
if [ -x "android/build-libs.sh" ]; then
    ./android/build-libs.sh
else
    echo "❌ Build script not found or not executable."
    exit 1
fi

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "JNI libraries are ready at:"
find android/SentinelPass/app/src/main/jniLibs -name "*.so"
echo ""
echo "Next steps:"
echo "  1. Open Android Studio"
echo "  2. Open project: android/SentinelPass"
echo "  3. Create an emulator (Device Manager → Create Device)"
echo "  4. Click Run to test the app"
echo ""
