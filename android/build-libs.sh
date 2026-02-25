#!/bin/bash
# Build JNI libraries for Android
#
# Requirements:
# 1. Android NDK installed
# 2. Rust targets installed: rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
# 3. NDK in PATH or set ANDROID_NDK_HOME

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect NDK
if [ -n "$ANDROID_NDK_HOME" ]; then
    NDK="$ANDROID_NDK_HOME"
elif [ -n "$ANDROID_NDK" ]; then
    NDK="$ANDROID_NDK"
elif [ -d "$HOME/Library/Android/sdk/ndk" ]; then
    # macOS default path
    NDK=$(ls -d "$HOME/Library/Android/sdk/ndk"* 2>/dev/null | sort -V | tail -1)
elif [ -d "$HOME/Android/Sdk/ndk" ]; then
    # Linux default path
    NDK=$(ls -d "$HOME/Android/Sdk/ndk"* 2>/dev/null | sort -V | tail -1)
else
    echo -e "${RED}Error: Android NDK not found${NC}"
    echo "Install via Android Studio: Settings → Appearance & Behavior → System Settings → Android SDK → SDK Tools → NDK (Side by side)"
    echo "Then set ANDROID_NDK_HOME environment variable"
    exit 1
fi

echo -e "${GREEN}Using NDK: $NDK${NC}"

# Set up toolchain paths
export PATH="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"

# Detect host
case "$(uname -s)" in
    Darwin*) HOST="darwin-x86_64" ;;
    Linux*)  HOST="linux-x86_64" ;;
    MINGW*|MSYS*|CYGWIN*) HOST="windows-x86_64" ;;
    *)
        echo -e "${RED}Unknown host: $(uname -s)${NC}"
        exit 1
        ;;
esac

export PATH="$NDK/toolchains/llvm/prebuilt/$HOST/bin:$PATH"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${YELLOW}Building Android JNI libraries...${NC}\n"

# Build for each architecture
ARCHS=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "x86_64-linux-android:x86_64"
)

for arch_pair in "${ARCHS[@]}"; do
    IFS=':' read -r rust_arch android_arch <<< "$arch_pair"

    echo -e "${GREEN}Building for $android_arch ($rust_arch)...${NC}"

    cargo build \
        --package sentinelpass-mobile-bridge \
        --features jni \
        --release \
        --target "$rust_arch" \
        2>&1 | grep -E "(Compiling|Finished|error)" || true

    # Copy to jniLibs
    mkdir -p "android/SentinelPass/app/src/main/jniLibs/$android_arch"
    cp "target/$rust_arch/release/libsentinelpass_mobile_bridge.so" \
       "android/SentinelPass/app/src/main/jniLibs/$android_arch/"

    echo -e "${GREEN}✓ Built $android_arch${NC}\n"
done

echo -e "${GREEN}All JNI libraries built successfully!${NC}"
echo ""
echo "Library locations:"
find android/SentinelPass/app/src/main/jniLibs -name "*.so"
