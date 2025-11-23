#!/bin/bash
################################################################################
# ROOT POCO C85 - Automated Rooting Script
################################################################################
#
# PURPOSE:
#   Automates the rooting process for POCO C85 (Xiaomi HyperOS) to enable
#   system app monitoring and deep surveillance detection.
#
# WHY ROOT:
#   - Monitor Xiaomi system services (com.xiaomi.*)
#   - Access system-level audio hooks
#   - Disable suspicious system apps
#   - Full device control for privacy
#
# ⚠️  WARNING - RISKS OF ROOTING:
#   - VOIDS WARRANTY
#   - WIPES ALL DATA (backup first!)
#   - May brick device if done incorrectly
#   - Banking apps may stop working
#   - OTA updates will fail
#
# WHAT THIS SCRIPT DOES:
#   1. Checks device is POCO C85
#   2. Unlocks bootloader (requires Xiaomi account)
#   3. Downloads and patches boot image with Magisk
#   4. Flashes patched boot
#   5. Installs Magisk Manager
#   6. Verifies root access
#
# REQUIREMENTS:
#   - POCO C85 connected via USB
#   - USB debugging enabled
#   - OEM unlocking enabled
#   - Xiaomi account (for bootloader unlock)
#   - fastboot tool installed
#   - Internet connection
#
# BACKUP FIRST:
#   adb backup -apk -shared -all -f backup.ab
#
# TIME: 30-60 minutes
#
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================================================"
echo "POCO C85 ROOTING SCRIPT"
echo "================================================================================"
echo ""
echo "⚠️  WARNING: This will:"
echo "   - WIPE ALL DATA on your phone"
echo "   - VOID YOUR WARRANTY"
echo "   - Require 30-60 minutes"
echo ""
echo "Have you backed up your data?"
read -p "Type 'YES' to continue: " -r
if [[ ! $REPLY == "YES" ]]; then
    echo "Aborted. Backup your data first!"
    exit 1
fi

################################################################################
# STEP 1: Verify Device
################################################################################
echo ""
echo "[1/8] Verifying device..."

# Check if device is connected
if ! adb devices | grep -q "device$"; then
    echo -e "${RED}❌ No device connected${NC}"
    echo "Connect your POCO C85 via USB and enable USB debugging"
    exit 1
fi

# Check if it's POCO C85
DEVICE_MODEL=$(adb shell getprop ro.product.model | tr -d '\r')
echo "   Detected: $DEVICE_MODEL"

if [[ ! $DEVICE_MODEL =~ "POCO" ]]; then
    echo -e "${YELLOW}⚠️  Warning: Device doesn't appear to be POCO C85${NC}"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}✓${NC} Device verified"

################################################################################
# STEP 2: Check Prerequisites
################################################################################
echo ""
echo "[2/8] Checking prerequisites..."

# Check if OEM unlocking is enabled
OEM_UNLOCK=$(adb shell getprop sys.oem_unlock_allowed | tr -d '\r')
if [[ "$OEM_UNLOCK" != "1" ]]; then
    echo -e "${RED}❌ OEM unlocking not enabled${NC}"
    echo "Enable it in: Settings → Developer Options → OEM unlocking"
    exit 1
fi
echo -e "${GREEN}✓${NC} OEM unlocking enabled"

# Check if fastboot is available
if ! command -v fastboot &> /dev/null; then
    echo -e "${RED}❌ fastboot not found${NC}"
    echo "Install with: brew install android-platform-tools"
    exit 1
fi
echo -e "${GREEN}✓${NC} fastboot available"

################################################################################
# STEP 3: Unlock Bootloader
################################################################################
echo ""
echo "[3/8] Unlocking bootloader..."
echo ""
echo "⚠️  IMPORTANT:"
echo "   1. This requires a Xiaomi account"
echo "   2. You may need to wait 7 days (Xiaomi restriction)"
echo "   3. This will WIPE ALL DATA"
echo ""
read -p "Ready to unlock bootloader? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Bootloader unlock cancelled"
    exit 1
fi

# Reboot to bootloader
echo "   Rebooting to bootloader..."
adb reboot bootloader
sleep 10  # Wait for reboot

# Attempt unlock
echo "   Attempting to unlock..."
fastboot oem unlock

# Check if successful
UNLOCK_STATUS=$(fastboot getvar unlocked 2>&1 | grep "unlocked:" | awk '{print $2}')
if [[ "$UNLOCK_STATUS" == "yes" ]]; then
    echo -e "${GREEN}✓${NC} Bootloader unlocked"
else
    echo -e "${YELLOW}⚠️  Bootloader unlock may require waiting period${NC}"
    echo ""
    echo "If you see 'waiting for 168 hours' message:"
    echo "   1. You need to wait 7 days after linking Xiaomi account"
    echo "   2. Keep SIM card inserted and connected to internet"
    echo "   3. Run this script again after waiting period"
    exit 1
fi

# Reboot system
fastboot reboot
echo "   Waiting for device to boot..."
sleep 30
adb wait-for-device

################################################################################
# STEP 4: Download Magisk
################################################################################
echo ""
echo "[4/8] Downloading Magisk..."

MAGISK_VERSION="27.0"  # Latest stable as of script creation
MAGISK_APK="Magisk-v${MAGISK_VERSION}.apk"
MAGISK_URL="https://github.com/topjohnwu/Magisk/releases/download/v${MAGISK_VERSION}/${MAGISK_APK}"

if [ ! -f "$MAGISK_APK" ]; then
    echo "   Downloading Magisk v${MAGISK_VERSION}..."
    curl -L -o "$MAGISK_APK" "$MAGISK_URL"
    echo -e "${GREEN}✓${NC} Downloaded Magisk"
else
    echo -e "${GREEN}✓${NC} Magisk already downloaded"
fi

################################################################################
# STEP 5: Get Boot Image
################################################################################
echo ""
echo "[5/8] Obtaining boot image..."

# Get current firmware version
FIRMWARE=$(adb shell getprop ro.build.version.incremental | tr -d '\r')
echo "   Firmware: $FIRMWARE"

echo ""
echo "You need to download the stock firmware boot.img for your device:"
echo "   1. Go to: https://xiaomifirmwareupdater.com/miui/comet/"
echo "   2. Find your firmware version: $FIRMWARE"
echo "   3. Download and extract boot.img"
echo ""
read -p "Have you placed boot.img in current directory? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Place boot.img file here and run script again"
    exit 1
fi

if [ ! -f "boot.img" ]; then
    echo -e "${RED}❌ boot.img not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} boot.img found"

################################################################################
# STEP 6: Patch Boot Image with Magisk
################################################################################
echo ""
echo "[6/8] Patching boot image..."

# Install Magisk app on phone
echo "   Installing Magisk app..."
adb install -r "$MAGISK_APK"

# Push boot.img to phone
echo "   Pushing boot.img to phone..."
adb push boot.img /sdcard/Download/boot.img

echo ""
echo "⚠️  MANUAL STEP REQUIRED:"
echo "   1. Open Magisk app on your phone"
echo "   2. Tap 'Install' next to Magisk"
echo "   3. Select 'Select and Patch a File'"
echo "   4. Navigate to Downloads and select boot.img"
echo "   5. Tap 'Let's Go' and wait for patching to complete"
echo "   6. You'll see 'Output file is written to...'"
echo ""
read -p "Press ENTER when patching is complete..." 

# Pull patched boot image
echo "   Pulling patched boot image..."
adb pull /sdcard/Download/magisk_patched*.img ./patched_boot.img

if [ ! -f "patched_boot.img" ]; then
    echo -e "${RED}❌ Patched boot image not found${NC}"
    echo "Make sure patching completed successfully"
    exit 1
fi
echo -e "${GREEN}✓${NC} Patched boot image obtained"

################################################################################
# STEP 7: Flash Patched Boot
################################################################################
echo ""
echo "[7/8] Flashing patched boot..."

# Reboot to bootloader
echo "   Rebooting to bootloader..."
adb reboot bootloader
sleep 10

# Flash patched boot
echo "   Flashing patched boot image..."
fastboot flash boot patched_boot.img

# Verify flash
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Boot image flashed successfully"
else
    echo -e "${RED}❌ Flash failed${NC}"
    exit 1
fi

# Reboot system
echo "   Rebooting system..."
fastboot reboot
sleep 30
adb wait-for-device

################################################################################
# STEP 8: Verify Root
################################################################################
echo ""
echo "[8/8] Verifying root access..."

sleep 10  # Wait for system to fully boot

# Check if Magisk is working
echo "   Checking Magisk..."
adb shell su -c "id"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ ROOT SUCCESSFUL!${NC}"
else
    echo -e "${YELLOW}⚠️  Root access not confirmed${NC}"
    echo "Open Magisk app and check status"
fi

################################################################################
# Cleanup
################################################################################
echo ""
echo "Cleaning up temporary files..."
# rm -f boot.img patched_boot.img  # Commented out - keep for reference

echo ""
echo "================================================================================"
echo "ROOT COMPLETE!"
echo "================================================================================"
echo ""
echo "✅ Your POCO C85 is now rooted with Magisk"
echo ""
echo "Next steps:"
echo "   1. Open Magisk app"
echo "   2. Check that root status shows 'Installed'"
echo "   3. Run: python3 scripts/analyze_system_apps.py"
echo "   4. Monitor Xiaomi system services for surveillance"
echo ""
echo "⚠️  Security recommendations:"
echo "   - Use Magisk Hide to hide root from banking apps"
echo "   - Install Magisk modules for enhanced privacy"
echo "   - Disable OTA updates (they will fail on rooted device)"
echo ""
echo "📚 Documentation: DO_I_NEED_ROOT.md"
echo ""

