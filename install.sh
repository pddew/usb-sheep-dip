#!/bin/bash
# Installation script for USB Sheep Dip Scanner on Raspberry Pi

set -e

echo "=========================================="
echo "USB Sheep Dip Scanner - Installation"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "[1/6] Updating system..."
apt-get update

echo "[2/6] Installing required packages..."
apt-get install -y \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    python3-pip \
    python3-pyudev \
    yara \
    ntfs-3g \
    exfat-fuse \
    exfat-utils

echo "[3/6] Installing Python dependencies..."
pip3 install pyudev --break-system-packages

echo "[4/6] Updating ClamAV virus definitions (this may take a while)..."
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam
systemctl start clamav-freshclam

echo "[5/6] Setting up directories..."
mkdir -p /mnt/usb_scan
mkdir -p /var/log/usb_sheep_dip
mkdir -p /var/quarantine
mkdir -p /usr/local/share/yara-rules

echo "[6/6] Installing scanner script..."
cp usb_sheep_dip.py /usr/local/bin/
chmod +x /usr/local/bin/usb_sheep_dip.py

# Create systemd service (optional)
cat > /etc/systemd/system/usb-sheep-dip.service << 'SERVICEEOF'
[Unit]
Description=USB Sheep Dip Scanner
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/usb_sheep_dip.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SERVICEEOF

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To run the scanner:"
echo "  Manual scan:    sudo /usr/local/bin/usb_sheep_dip.py /dev/sda1"
echo "  Auto-monitor:   sudo /usr/local/bin/usb_sheep_dip.py"
echo ""
echo "To enable automatic scanning on boot:"
echo "  sudo systemctl enable usb-sheep-dip"
echo "  sudo systemctl start usb-sheep-dip"
echo ""
echo "Logs are stored in: /var/log/usb_sheep_dip/"
echo ""
