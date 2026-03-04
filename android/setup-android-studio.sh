#!/bin/bash
# Android Studio First Launch Setup Guide

echo "=== Android Studio Setup Guide ==="
echo ""
echo "Android Studio has been detected. Let's complete the setup:"
echo ""

echo "STEP 1: First Launch Setup"
echo "--------------------------"
echo "1. Open Android Studio:"
echo "   open -a 'Android Studio'"
echo ""
echo "2. Complete the setup wizard:"
echo "   - Choose 'Standard' installation"
echo "   - This will download:"
echo "     • Android SDK (~2 GB)"
echo "     • Android SDK Platform-Tools"
echo "     • Android SDK Build-Tools"
echo "     • Emulator (with system images)"
echo ""
echo "3. After setup completes, install the NDK:"
echo "   - Tools → SDK Manager"
echo "   - Click 'SDK Tools' tab"
echo "   - Check 'NDK (Side by side)'"
echo "   - Click 'Apply' (downloads ~1 GB)"
echo "   - Click 'OK'"
echo ""

echo "STEP 2: Verify Installation"
echo "---------------------------"
echo "After Android Studio finishes downloading, run this script again:"
echo ""
echo "   ./android/verify-android-setup.sh"
echo ""

echo "STEP 3: Build JNI Libraries"
echo "----------------------------"
echo "Once NDK is installed, build the native libraries:"
echo ""
echo "   ./android/build-libs.sh"
echo ""

echo "STEP 4: Create Emulator"
echo "----------------------"
echo "In Android Studio:"
echo "   - Device Manager (phone icon in toolbar)"
echo "   - Create Device"
echo "   - Select: Pixel 6 or Pixel 7"
echo "   - System Image: API 34 (Android 14) or API 35"
echo "   - Finish"
echo ""

echo "STEP 5: Run the App"
echo "-----------------"
echo "   - Open project: android/SentinelPass"
echo "   - Select emulator from device dropdown"
echo "   - Click Run (green play button)"
echo ""

# Check if we can detect Android tools
if [ -d "$HOME/Library/Android/sdk" ]; then
    echo "✓ Android SDK detected at: $HOME/Library/Android/sdk"
    SDK_PATH="$HOME/Library/Android/sdk"
elif [ -d "$HOME/Android/Sdk" ]; then
    echo "✓ Android SDK detected at: $HOME/Android/Sdk"
    SDK_PATH="$HOME/Android/Sdk"
else
    echo "⚠ Android SDK not yet installed."
    echo "  Open Android Studio and complete the setup wizard first."
fi

# Check for NDK
if [ -n "$SDK_PATH" ]; then
    NDK_PATH=$(ls -d "$SDK_PATH"/ndk/* 2>/dev/null | sort -V | tail -1)
    if [ -n "$NDK_PATH" ]; then
        echo "✓ NDK detected at: $NDK_PATH"
        echo ""
        echo "You're ready to build! Run:"
        echo "  ./android/build-libs.sh"
    else
        echo "⚠ NDK not found."
        echo "  Open Android Studio → Tools → SDK Manager → SDK Tools → Check 'NDK (Side by side)'"
    fi
fi

echo ""
echo "=== Ready to Proceed ==="
echo ""
