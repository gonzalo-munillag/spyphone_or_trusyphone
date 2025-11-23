#!/bin/bash
################################################################################
# SpyPhone Investigation - Automated Setup Script for macOS
################################################################################
#
# PURPOSE:
#   Automates the installation of all required tools and dependencies
#   for mobile surveillance detection on macOS systems.
#
# WHAT IT INSTALLS:
#   1. Homebrew - macOS package manager
#   2. Android Platform Tools (ADB) - Device communication
#   3. Python 3 and pip - Scripting environment
#   4. Python packages (Frida, scapy, etc.) - Analysis tools
#   5. Wireshark - Network packet analyzer
#   6. mitmproxy - HTTPS proxy for traffic decryption
#
# REQUIREMENTS:
#   - macOS (tested on M1 Pro)
#   - Internet connection
#   - Admin privileges (for Homebrew installation)
#   - ~500MB disk space
#
# USAGE:
#   ./setup.sh
#
# TIME: ~15-30 minutes depending on internet speed
#
################################################################################

# Exit immediately if any command fails (safe scripting practice)
set -e

echo "=========================================="
echo "SpyPhone Investigation - Setup"
echo "=========================================="
echo ""

################################################################################
# Color codes for pretty terminal output
################################################################################
RED='\033[0;31m'      # For errors
GREEN='\033[0;32m'    # For success messages
YELLOW='\033[1;33m'   # For warnings
NC='\033[0m'          # No Color (reset)

################################################################################
# Platform Check - Only macOS is supported
################################################################################
# This script uses Homebrew which is macOS-specific
# For Linux, use apt/yum; for Windows, use WSL or manual installation
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}Error: This script is designed for macOS${NC}"
    echo "For other systems, please follow the manual setup instructions in README.md"
    exit 1
fi

echo "This script will install:"
echo "  - Homebrew (if not installed)"
echo "  - Android Platform Tools (ADB)"
echo "  - Python 3 and dependencies"
echo "  - Frida and Frida tools"
echo "  - Network analysis tools (Wireshark, mitmproxy)"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled"
    exit 1
fi

################################################################################
# STEP 1/7: Install Homebrew (macOS Package Manager)
################################################################################
# Homebrew is like apt-get for macOS - manages software installation
# Official site: https://brew.sh
echo ""
echo "[1/7] Checking Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "  → Installing Homebrew..."
    echo "  (This may take a few minutes and require your password)"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo -e "  ${GREEN}✓${NC} Homebrew already installed"
fi

################################################################################
# STEP 2/7: Install Android Debug Bridge (ADB)
################################################################################
# ADB is the command-line tool for communicating with Android devices
# Required for:
#   - Installing Frida server on phone
#   - Pulling network captures
#   - Accessing device logs
#   - Running remote commands
echo ""
echo "[2/7] Installing Android Platform Tools..."
if ! command -v adb &> /dev/null; then
    echo "  → Installing ADB..."
    brew install android-platform-tools
    echo -e "  ${GREEN}✓${NC} ADB installed"
else
    echo -e "  ${GREEN}✓${NC} ADB already installed"
fi

################################################################################
# STEP 3/7: Install Python 3
################################################################################
# Python 3 is required for:
#   - Frida Python bindings
#   - Analysis scripts (monitoring, correlation, analysis)
#   - Data processing libraries (scapy, pandas, etc.)
echo ""
echo "[3/7] Checking Python 3..."
if ! command -v python3 &> /dev/null; then
    echo "  → Installing Python 3..."
    brew install python3
    echo -e "  ${GREEN}✓${NC} Python 3 installed"
else
    echo -e "  ${GREEN}✓${NC} Python 3 already installed: $(python3 --version)"
fi

################################################################################
# STEP 4/7: Install Python Dependencies
################################################################################
# This installs all packages listed in requirements.txt:
#   - frida & frida-tools: Dynamic instrumentation framework
#   - scapy: Network packet manipulation
#   - pandas: Data analysis
#   - And many more...
# See requirements.txt for complete list
echo ""
echo "[4/7] Installing Python dependencies..."
echo "  (This may take 5-10 minutes...)"
pip3 install -r requirements.txt
echo -e "  ${GREEN}✓${NC} Python dependencies installed"

################################################################################
# STEP 5/7: Install Wireshark (Network Packet Analyzer)
################################################################################
# Wireshark captures and analyzes network traffic
# Used for:
#   - Viewing all data sent/received by phone
#   - Identifying suspicious uploads
#   - Correlating network activity with audio access
#   - Detecting connections to foreign servers
echo ""
echo "[5/7] Installing Wireshark..."
if ! command -v wireshark &> /dev/null; then
    echo "  → Installing Wireshark..."
    brew install --cask wireshark
    echo -e "  ${GREEN}✓${NC} Wireshark installed"
else
    echo -e "  ${GREEN}✓${NC} Wireshark already installed"
fi

################################################################################
# STEP 6/7: Install mitmproxy (HTTPS Decryption Tool)
################################################################################
# mitmproxy is an interactive HTTPS proxy
# Used for:
#   - Decrypting HTTPS traffic (with certificate installation)
#   - Seeing actual content of encrypted uploads
#   - Identifying what data is being exfiltrated
#   - Works by acting as "man-in-the-middle"
echo ""
echo "[6/7] Installing mitmproxy..."
if ! command -v mitmproxy &> /dev/null; then
    echo "  → Installing mitmproxy..."
    brew install mitmproxy
    echo -e "  ${GREEN}✓${NC} mitmproxy installed"
else
    echo -e "  ${GREEN}✓${NC} mitmproxy already installed"
fi

################################################################################
# STEP 7/7: Verify Installation
################################################################################
# Run quick checks to ensure all critical components are working
# If any show ✗ (red X), the installation had issues
echo ""
echo "[7/7] Verifying installation..."
echo ""

# Check Frida (Most critical - the heart of our detection)
if python3 -c "import frida" 2>/dev/null; then
    FRIDA_VERSION=$(python3 -c "import frida; print(frida.__version__)")
    echo -e "  ${GREEN}✓${NC} Frida: $FRIDA_VERSION"
else
    echo -e "  ${RED}✗${NC} Frida: Not installed properly"
    echo -e "      Try: pip3 install --upgrade frida frida-tools"
fi

# Check ADB (Required for device communication)
if command -v adb &> /dev/null; then
    ADB_VERSION=$(adb version | head -1)
    echo -e "  ${GREEN}✓${NC} ADB: $ADB_VERSION"
else
    echo -e "  ${RED}✗${NC} ADB: Not found"
    echo -e "      Try: brew install android-platform-tools"
fi

# Check Scapy (For network analysis)
if python3 -c "import scapy" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Scapy: Installed"
else
    echo -e "  ${YELLOW}!${NC} Scapy: Warning - may not work properly"
    echo -e "      Network analysis might be limited"
fi

################################################################################
# Setup Complete! Next Steps for You
################################################################################
echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "📱 NEXT STEPS:"
echo ""
echo "1. CONNECT YOUR ANDROID DEVICE:"
echo "   • Plug phone into Mac via USB cable"
echo ""
echo "2. ENABLE DEVELOPER MODE ON PHONE:"
echo "   • Go to: Settings → About Phone"
echo "   • Tap 'MIUI/HyperOS Version' 7 times rapidly"
echo "   • You'll see: 'You are now a developer!'"
echo ""
echo "3. ENABLE USB DEBUGGING:"
echo "   • Go to: Settings → Additional Settings → Developer Options"
echo "   • Enable 'USB Debugging'"
echo "   • Enable 'Install via USB' (if available)"
echo "   • Connect phone, accept authorization prompt"
echo ""
echo "4. VERIFY DEVICE CONNECTION:"
echo "   Run: adb devices"
echo "   You should see your device ID with 'device' status"
echo "   (If 'unauthorized', check phone for popup)"
echo ""
echo "5. INSTALL FRIDA SERVER ON PHONE:"
echo "   • Check architecture: adb shell getprop ro.product.cpu.abi"
echo "   • Download matching version from:"
echo "     https://github.com/frida/frida/releases/tag/$FRIDA_VERSION"
echo "   • Look for: frida-server-$FRIDA_VERSION-android-arm64.xz"
echo "   • Extract: unxz frida-server-*.xz"
echo "   • Push: adb push frida-server-* /data/local/tmp/frida-server"
echo "   • Permissions: adb shell 'chmod 755 /data/local/tmp/frida-server'"
echo "   • Start: adb shell '/data/local/tmp/frida-server &'"
echo "   • Verify: frida-ps -U (should list phone processes)"
echo ""
echo "6. START YOUR INVESTIGATION:"
echo "   Read: cat QUICKSTART.md"
echo "   Then run: python3 scripts/monitor_baseline.py"
echo ""
echo "📚 For detailed step-by-step instructions:"
echo "   • Quick start: QUICKSTART.md"
echo "   • Full guide: README.md"
echo "   • Technical details: TECHNICAL_EXPLAINED.md"
echo ""
echo "🔍 Ready to find out if your €92 phone is spying on you!"
echo ""

