#!/bin/bash
# Quick script to build and run SentinelPass Android app

set -e

echo "=== SentinelPass Android Build & Run ==="
echo ""

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd "$PROJECT_ROOT/.." && pwd"
cd "$PROJECT_ROOT"

echo "Waiting for emulator..."
echo "(You should see the Android home screen in the emulator window)"
echo ""

# Wait for device
MAX_WAIT=60
count=0
while [ $count -lt $MAX_WAIT ]; do
    if adb devices 2>/dev/null | grep -q "device$"; then
        echo "✓ Emulator ready!"
        break
    fi
    sleep 2
    count=$((count + 2))
    echo -n "."
done
echo ""

if [ $count -ge $MAX_WAIT ]; then
    echo "Emulator not ready. Please:"
    echo "  1. Check Android Studio emulator window"
    echo "  2. Wait for Android home screen to appear"
    echo "  3. Then run this script again"
    exit 1
fi

echo "Building APK..."
cd android/SentinelPass

# Build and install
./gradlew assembleDebug

echo ""
echo "Installing on emulator..."
./gradlew installDebug

echo ""
echo "Launching SentinelPass..."
adb shell am start -n com.sentinelpass/.MainActivity

echo ""
echo "✓ App should now be running on the emulator!"
echo ""
echo "Look for the SentinelPass app on the emulator home screen."
