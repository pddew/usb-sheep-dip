# USB Sheep Dip Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-3B%2B%20%7C%204%20%7C%205-red.svg)](https://www.raspberrypi.org/)

Turn a Raspberry Pi into an air-gapped malware scanning station for USB drives. This tool provides automated detection and scanning of USB devices using ClamAV antivirus, YARA pattern matching, and filesystem analysis.

## Features

- **Automatic USB Detection**: Monitors for USB insertion and scans automatically
- **Multi-layered Scanning**:
  - ClamAV antivirus scanning
  - YARA rule matching (optional)
  - Filesystem analysis for suspicious files
  - SHA256 hash calculation
- **Read-only Mounting**: USB drives are mounted read-only with noexec for safety
- **Detailed Logging**: All scans are logged with timestamps and results
- **Manual or Automatic Mode**: Run one-time scans or continuous monitoring

## Hardware Requirements

- Raspberry Pi (Model 3B+ or newer recommended)
- MicroSD card (16GB+ recommended)
- Power supply
- Optional: LCD screen for standalone operation

## Installation

1. **Flash Raspberry Pi OS** (Lite or Desktop) to your SD card

2. **Transfer the files** to your Raspberry Pi:
   ```bash
   git clone https://github.com/pddew/usb-sheep-dip.git
   cd usb-sheep-dip
   ```

3. **Run the installation script**:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

   The installation script will:
   - Install ClamAV antivirus
   - Install YARA rule engine
   - Install Python dependencies
   - Update virus definitions
   - Set up necessary directories
   - Install the scanner script

## Usage

### Manual Scan Mode

Scan a specific USB device:
```bash
sudo /usr/local/bin/usb_sheep_dip.py /dev/sda1
```

Replace `/dev/sda1` with your USB device path (check with `lsblk`)

### Automatic Monitoring Mode

Start continuous monitoring for USB insertion:
```bash
sudo /usr/local/bin/usb_sheep_dip.py
```

The scanner will automatically detect and scan any USB drive that's inserted.

### Run as a Service (Auto-start on Boot)

Enable the systemd service:
```bash
sudo systemctl enable usb-sheep-dip
sudo systemctl start usb-sheep-dip
```

Check status:
```bash
sudo systemctl status usb-sheep-dip
```

View live logs:
```bash
sudo journalctl -u usb-sheep-dip -f
```

## How It Works

1. **USB Detection**: Monitors for USB device insertion using pyudev
2. **Safe Mounting**: Mounts the USB drive read-only with security flags (noexec, nosuid, nodev)
3. **Scanning Process**:
   - ClamAV scans all files for known malware signatures
   - YARA rules check for suspicious patterns
   - Filesystem analysis identifies potentially dangerous file types
   - All files are hashed for forensic purposes
4. **Reporting**: Results are displayed on screen and logged to files
5. **Safe Unmounting**: USB is unmounted after scanning

## Log Files

All scan results are stored in `/var/log/usb_sheep_dip/`:
- Daily log files: `scan_YYYYMMDD.log`
- Detailed JSON reports: `scan_YYYYMMDD_HHMMSS.json`

## Security Considerations

### What This Scanner Does:
- ✅ Detects known malware signatures using ClamAV
- ✅ Identifies suspicious file patterns
- ✅ Prevents execution of code on USB drives
- ✅ Provides forensic information (hashes, file listings)

### What This Scanner CANNOT Do:
- ❌ Detect zero-day or highly sophisticated malware
- ❌ Analyze obfuscated or encrypted payloads
- ❌ Guarantee 100% safety (no scanner can)
- ❌ Protect against hardware-level attacks (BadUSB)

### Best Practices:
1. **Keep virus definitions updated**: Run `sudo freshclam` regularly
2. **Use on an isolated network**: Don't connect this Pi to your production network
3. **Review suspicious files manually**: Check flagged files before clearing a USB
4. **Maintain a separate scanning station**: Don't use this Pi for other purposes
5. **Layer your security**: This is one tool in a defense-in-depth strategy

## Updating Virus Definitions

ClamAV definitions should update automatically, but you can manually update:
```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

## Adding Custom YARA Rules

Place YARA rule files (.yar) in: `/usr/local/share/yara-rules/`

Example rules can be found at:
- https://github.com/Yara-Rules/rules
- https://github.com/reversinglabs/reversinglabs-yara-rules

## Troubleshooting

### USB not detected
- Check `lsblk` to see if the USB is recognized
- Try `sudo dmesg | tail` to see kernel messages
- Ensure USB is properly formatted (FAT32, NTFS, exFAT supported)

### Permission denied errors
- Make sure you're running with `sudo`
- Check that directories have proper permissions

### ClamAV scan very slow
- This is normal for large USB drives
- Consider increasing the timeout in the script
- Ensure your Pi has adequate cooling

### Service won't start
- Check logs: `sudo journalctl -u usb-sheep-dip -xe`
- Verify Python path: `which python3`
- Test script manually first

## Customization

Edit `/usr/local/bin/usb_sheep_dip.py` to customize:
- Scan timeouts
- Suspicious file patterns
- Logging verbosity
- Additional scanning tools

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for legitimate security purposes. Always ensure you have authorization to scan devices and comply with applicable laws and regulations. This software is provided as-is without warranty of any kind.
