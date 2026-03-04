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
    echo "Install via Android Studio: Tools → SDK Manager → SDK Tools → NDK (Side by side)"
    echo "Then set ANDROID_NDK_HOME environment variable"
    exit 1
fi

echo -e "${GREEN}Using NDK: $NDK${NC}"

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

    # Set environment for this architecture
    export TARGET="$rust_arch"
    export ANDROID_NDK_HOME="$NDK"
    export PATH="$NDK/toolchains/llvm/prebuilt/$HOST/bin:$PATH"

    # Set cargo flags for Android NDK linking
    export CARGO_TARGET_APPLINK="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android28-clang"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android28-clang"
    export CC_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android28-clang"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-ar"
    export AR_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-ar"
    export CMAKE_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/$HOST/bin/cmake"

    if [[ "$rust_arch" == "armv7-linux-androideabi" ]]; then
        export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK/toolchains/llvm/prebuilt/$HOST/bin/armv7-linux-androideabi28-clang"
        export CC_armv7_linux_androideabi="$NDK/toolchains/llvm/prebuilt/$HOST/bin/armv7-linux-androideabi28-clang"
        export AR_armv7_linux_androideabi="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-ar"
    elif [[ "$rust_arch" == "x86_64-linux-android" ]]; then
        export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK/toolchains/llvm/prebuilt/$HOST/bin/x86_64-linux-android28-clang"
        export CC_x86_64_linux_android="$NDK/toolchains/llvm/prebuilt/$HOST/bin/x86_64-linux-android28-clang"
        export AR_x86_64_linux_android="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-ar"
    fi

    cargo build \
        --package sentinelpass-mobile-bridge \
        --features jni \
        --release \
        --target "$rust_arch" \
        2>&1 | grep -E "(Compiling|Finished|error|warning: unused)" || true

    # Check if build succeeded
    if [ -f "target/$rust_arch/release/libsentinelpass_mobile_bridge.so" ]; then
        # Copy to jniLibs
        mkdir -p "android/SentinelPass/app/src/main/jniLibs/$android_arch"
        cp "target/$rust_arch/release/libsentinelpass_mobile_bridge.so" \
           "android/SentinelPass/app/src/main/jniLibs/$android_arch/"
        echo -e "${GREEN}✓ Built $android_arch${NC}\n"
    else
        echo -e "${RED}✗ Failed to build $android_arch${NC}"
        echo "Check the error messages above for details.\n"
    fi
done

# Check if any libraries were built
if find android/SentinelPass/app/src/main/jniLibs -name "*.so" | grep -q .; then
    echo -e "${GREEN}JNI libraries built successfully!${NC}"
    echo ""
    echo "Library locations:"
    find android/SentinelPass/app/src/main/jniLibs -name "*.so"
else
    echo -e "${RED}No JNI libraries were built.${NC}"
    echo "Please check the error messages above."
    exit 1
fi
