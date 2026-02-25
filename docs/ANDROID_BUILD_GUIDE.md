# Android App Build Guide

This guide explains how to build the SentinelPass Android app from source.

## Prerequisites

- Android Studio Hedgehog (2023.1.1) or later
- JDK 17
- Android SDK 34
- Android NDK 25.x or later
- Rust stable toolchain

## Step 1: Install Android NDK

The NDK is required to build the Rust library for Android.

### Via Android Studio

1. Open Android Studio
2. Settings → Appearance & Behavior → System Settings → Android SDK
3. Go to "SDK Tools" tab
4. Check "NDK (Side by side)"
5. Click "Apply" to install

### Verify Installation

```bash
# Check NDK version
$ANDROID_NDK_HOME/ndk-build
# Should output version like: 25.2.9519653
```

## Step 2: Install Rust Android Targets

```bash
# Install Android Rust targets
rustup target add aarch64-linux-android    # arm64-v8a
rustup target add armv7-linux-androideabi  # armeabi-v7a
rustup target add x86_64-linux-android     # x86_64
```

## Step 3: Build the Rust Mobile Bridge

The mobile bridge needs to be built for each Android architecture:

```bash
cd /path/to/sentinelpass

# Build for arm64-v8a (most physical devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target aarch64-linux-android

# Build for armeabi-v7a (older 32-bit devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target armv7-linux-androideabi

# Build for x86_64 (emulators)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target x86_64-linux-android
```

The compiled libraries will be at:
- `target/aarch64-linux-android/release/libsentinelpass_mobile_bridge.so`
- `target/armv7-linux-androideabi/release/libsentinelpass_mobile_bridge.so`
- `target/x86_64-linux-android/release/libsentinelpass_mobile_bridge.so`

## Step 4: Copy JNI Libraries

Create the JNI libs directory and copy the built libraries:

```bash
# Create directory structure
mkdir -p android/SentinelPass/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

# Copy libraries
cp target/aarch64-linux-android/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/armeabi-v7a/

cp target/x86_64-linux-android/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/x86_64/
```

## Step 5: Open in Android Studio

```bash
cd android/SentinelPass
# Or open Android Studio and select "Open an Existing Project"
```

## Step 6: Configure Gradle

Make sure `app/build.gradle.kts` has the correct NDK configuration:

```kotlin
ndk {
    abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
}
```

## Step 7: Build and Run

### From Android Studio

1. Select a device or emulator from the device dropdown
2. Click "Run" (green play button) or press `Shift+F10`

### From Command Line

```bash
# Build debug APK
./gradlew assembleDebug

# Build release APK
./gradlew assembleRelease

# Install debug APK to connected device
./gradlew installDebug
```

The APK will be at:
- Debug: `app/build/outputs/apk/debug/app-debug.apk`
- Release: `app/build/outputs/apk/release/app-release-unsigned.apk`

## Signing Release APK

To distribute the app, you need to sign the release APK:

### 1. Create Keystore

```bash
keytool -genkey -v -keystore sentinelpass-release.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias sentinelpass
```

### 2. Configure Signing in `app/build.gradle.kts`

```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file("sentinelpass-release.jks")
            storePassword = "your-store-password"
            keyAlias = "sentinelpass"
            keyPassword = "your-key-password"
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

**Security Note**: Never commit the keystore or passwords to version control. Use environment variables or `local.properties`:

```kotlin
// In local.properties (not committed)
RELEASE_STORE_FILE=sentinelpass-release.jks
RELEASE_STORE_PASSWORD=your-store-password
RELEASE_KEY_ALIAS=sentinelpass
RELEASE_KEY_PASSWORD=your-key-password

// In build.gradle.kts
val keystorePropertiesFile = rootProject.file("local.properties")
val keystoreProperties = Properties()
keystoreProperties.load(FileInputStream(keystorePropertiesFile))

signingConfigs {
    create("release") {
        storeFile = file(keystoreProperties["RELEASE_STORE_FILE"] as String)
        storePassword = keystoreProperties["RELEASE_STORE_PASSWORD"] as String
        keyAlias = keystoreProperties["RELEASE_KEY_ALIAS"] as String
        keyPassword = keystoreProperties["RELEASE_KEY_PASSWORD"] as String
    }
}
```

### 3. Build Signed Release APK

```bash
./gradlew assembleRelease
```

### 4. Align and Zip

```bash
# Align APK (better performance)
$ANDROID_HOME/build-tools/34.0.0/zipalign -v -p 4 \
  app/build/outputs/apk/release/app-release-unsigned.apk \
  sentinelpass-release-aligned.apk

# Sign with apksigner
$ANDROID_HOME/build-tools/34.0.0/apksigner sign \
  --ks sentinelpass-release.jks \
  --ks-key-alias sentinelpass \
  --out sentinelpass-release.apk \
  sentinelpass-release-aligned.apk
```

## Building for Multiple Architectures

To reduce APK size, consider building APK splits:

```kotlin
android {
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            universalApk = false
        }
    }
}
```

This generates separate APKs for each architecture, which users can download via Play Store's automatic selection.

## Building Android App Bundle (AAB)

For Play Store distribution, use AAB instead of APK:

```kotlin
android {
    bundle {
        language {
            enableSplit = false
        }
        density {
            enableSplit = true
        }
        abi {
            enableSplit = true
        }
    }
}
```

Build AAB:

```bash
./gradlew bundleRelease
```

Output: `app/build/outputs/bundle/release/app-release.aab`

## Troubleshooting

### "Cannot find JNICALL function"

**Error**: `java.lang.UnsatisfiedLinkError: No implementation found for...`

**Solution**:
1. Verify library built with JNI feature: `--features jni`
2. Check function signatures match between Kotlin and Rust
3. Ensure package name matches: `Java_com_sentinelpass_VaultManager_native*`

### "Wrong ELF class: ELFCLASS64"

**Error**: Wrong architecture library for device

**Solution**:
- Check device architecture: `adb shell getprop ro.product.cpu.abi`
- Build only for required architectures
- Remove unused libraries from `jniLibs/`

### NDK not found

**Error**: `NDK not configured`

**Solution**:
1. Install NDK via Android Studio SDK Manager
2. Set `ndk.dir` in `local.properties`:
   ```
   ndk.dir=/path/to/android-sdk/ndk/25.2.9519653
   ```

### Build failures on Windows

**Error**: Path too long or special characters

**Solution**:
1. Move project closer to drive root (e.g., `C:\projects\sentinelpass`)
2. Enable long paths in Windows (Windows 10+):
   ```
   Enable-WindowsOptionalFeature -Online -FeatureName LongPaths
   ```

## Testing on Emulator

For biometric testing:

1. Run emulator with Google Play Support
2. Open Extended Controls (⌘E or ... button)
3. Navigate to "Biometric" settings
4. Add fingerprints or enable Face ID

## Continuous Integration

### GitHub Actions Example

```yaml
name: Android Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Set up JDK 17
      uses: actions/setup-java@v4
      with:
        java-version: '17'
        distribution: 'temurin'

    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true

    - name: Install Android targets
      run: |
        rustup target add aarch64-linux-android
        rustup target add x86_64-linux-android

    - name: Build mobile bridge
      run: |
        cargo build --package sentinelpass-mobile-bridge --features jni \
          --release --target aarch64-linux-android

    - name: Copy JNI libraries
      run: |
        mkdir -p android/SentinelPass/app/src/main/jniLibs/arm64-v8a
        cp target/aarch64-linux-android/release/libsentinelpass_mobile_bridge.so \
           android/SentinelPass/app/src/main/jniLibs/arm64-v8a/

    - name: Build Android app
      run: |
        cd android/SentinelPass
        ./gradlew assembleDebug

    - name: Upload APK
      uses: actions/upload-artifact@v4
      with:
        name: app-debug
        path: android/SentinelPass/app/build/outputs/apk/debug/app-debug.apk
```

## Next Steps

After building:

1. Test on physical Android device
2. Verify biometric authentication works
3. Test password CRUD operations
4. Test TOTP generation
5. Test password generator
6. Verify autofill service (if implemented)

For app usage guide, see `android/SentinelPass/README.md`.
