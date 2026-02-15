#!/bin/bash
# Password Manager Installation Script for macOS and Linux

set -e

BINARY_DIR_OVERRIDE="${SENTINELPASS_BINARY_DIR:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --binary-dir" >&2
                exit 1
            fi
            BINARY_DIR_OVERRIDE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option for installation/install.sh: $1" >&2
            exit 1
            ;;
    esac
done

# Detect platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    INSTALL_DIR="$HOME/Library/Application Support/SentinelPass"
    CHROME_PREFS_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    CHROME_FLAGS_DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
    FIREFOX_NATIVE_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
else
    PLATFORM="linux"
    INSTALL_DIR="$HOME/.local/share/sentinelpass"
    CHROME_PREFS_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    CHROME_FLAGS_DIR="$HOME/.config/chromium/NativeMessagingHosts"
    FIREFOX_NATIVE_DIR="$HOME/.mozilla/native-messaging-hosts"
fi

NATIVE_HOST_NAME="com.passwordmanager.host"
CHROME_MANIFEST_FILE="$NATIVE_HOST_NAME.json"
FIREFOX_MANIFEST_FILE="$NATIVE_HOST_NAME.firefox.json"
CHROME_EXTENSION_ID="${SENTINELPASS_CHROME_EXTENSION_ID:-YOUR_EXTENSION_ID_HERE}"

echo "Installing SentinelPass for $PLATFORM..."

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_DIR="${BINARY_DIR_OVERRIDE:-$PROJECT_ROOT/target/release}"

# Check if binaries are built
if [[ ! -d "$BINARY_DIR" ]]; then
    echo "Binary directory not found. Please run 'cargo build --release' first."
    exit 1
fi

# Check if binaries exist
if [[ ! -f "$BINARY_DIR/sentinelpass-host" ]] && [[ ! -f "$BINARY_DIR/sentinelpass-host.exe" ]]; then
    echo "sentinelpass-host binary not found in $BINARY_DIR"
    echo "Please run 'cargo build --release' first."
    exit 1
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy binaries (handle both Windows .exe and Unix binaries)
echo "Copying binaries..."
if [[ -f "$BINARY_DIR/sentinelpass-host" ]]; then
    cp "$BINARY_DIR/sentinelpass-host" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-host"
else
    cp "$BINARY_DIR/sentinelpass-host.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass-daemon" ]]; then
    cp "$BINARY_DIR/sentinelpass-daemon" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-daemon"
else
    cp "$BINARY_DIR/sentinelpass-daemon.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass-ui" ]]; then
    cp "$BINARY_DIR/sentinelpass-ui" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-ui"
else
    cp "$BINARY_DIR/sentinelpass-ui.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass" ]]; then
    cp "$BINARY_DIR/sentinelpass" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass"
elif [[ -f "$BINARY_DIR/sentinelpass.exe" ]]; then
    cp "$BINARY_DIR/sentinelpass.exe" "$INSTALL_DIR/"
fi

# Generate native messaging host manifest
echo "Installing native messaging host manifest..."

# Determine the binary path
if [[ -f "$INSTALL_DIR/sentinelpass-host" ]]; then
    BINARY_PATH="$INSTALL_DIR/sentinelpass-host"
else
    BINARY_PATH="$INSTALL_DIR/sentinelpass-host.exe"
fi

# Create Chrome/Chromium manifest JSON
cat > "$INSTALL_DIR/$CHROME_MANIFEST_FILE" << EOF
{
  "name": "com.passwordmanager.host",
  "description": "SentinelPass Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$CHROME_EXTENSION_ID/"
  ]
}
EOF

# Create Firefox manifest JSON
cat > "$INSTALL_DIR/$FIREFOX_MANIFEST_FILE" << EOF
{
  "name": "com.passwordmanager.host",
  "description": "SentinelPass Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "sentinelpass@localhost"
  ]
}
EOF

# Create native messaging host directories
mkdir -p "$CHROME_PREFS_DIR"
mkdir -p "$CHROME_FLAGS_DIR"
mkdir -p "$FIREFOX_NATIVE_DIR"

# Create symlinks to manifest
ln -sf "$INSTALL_DIR/$CHROME_MANIFEST_FILE" "$CHROME_PREFS_DIR/$NATIVE_HOST_NAME.json"
ln -sf "$INSTALL_DIR/$CHROME_MANIFEST_FILE" "$CHROME_FLAGS_DIR/$NATIVE_HOST_NAME.json"
ln -sf "$INSTALL_DIR/$FIREFOX_MANIFEST_FILE" "$FIREFOX_NATIVE_DIR/$NATIVE_HOST_NAME.json"

echo "Native messaging host registered for Chrome, Chromium, and Firefox"

if [[ "$CHROME_EXTENSION_ID" == "YOUR_EXTENSION_ID_HERE" ]]; then
    echo "WARNING: Chrome native host manifest still uses placeholder extension ID."
    echo "Set SENTINELPASS_CHROME_EXTENSION_ID=<32-char-id> before running install.sh, or edit $INSTALL_DIR/$CHROME_MANIFEST_FILE."
fi

# Add to PATH (if not already there)
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    SHELL_CONFIG=""
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        SHELL_CONFIG="$HOME/.bashrc"
    fi

    if [[ -n "$SHELL_CONFIG" ]]; then
        echo "" >> "$SHELL_CONFIG"
        echo "# SentinelPass" >> "$SHELL_CONFIG"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_CONFIG"
        echo "Added $INSTALL_DIR to PATH in $SHELL_CONFIG"
        echo "Run 'source $SHELL_CONFIG' or restart your shell to use the new PATH"
    fi
fi

echo ""
echo "Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Load the browser extension from browser-extension/chrome"
echo "2. (Optional) Load Firefox extension from browser-extension/firefox/manifest.json"
echo "3. Run 'sentinelpass init' to create a new vault"
echo "4. Start the UI: sentinelpass-ui"
echo "5. Use the browser extension to autofill passwords"
