# Bing Wallpaper Client (BWC)

[![PowerShell](https://img.shields.io/badge/PowerShell-3.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Windows-7%20|%208%20|%2010%20|%2011-blue.svg)](https://www.microsoft.com/windows)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Lightweight CLI tool for automatic Windows wallpaper rotation using Bing's daily images

>[!IMPORTANT]
> - This tool is not affiliated with Microsoft or Bing.
> - Requires PowerShell 3.0 or higher and Windows 7 or later.
> - BWC is in early development; basic features are functional, but major changes may occur in future releases.
> - Currently available only for Windows; support for other operating systems may be considered in the future.

## Table of Contents
- [Features](#features)
- [Why BWC?](#why-bwc)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [File Locations](#file-locations)
- [Scheduled Task](#scheduled-task)
- [Uninstallation](#uninstallation)
- [License](#license)

## Features

- **Automatic wallpaper updates** from Bing's daily featured images
- **Desktop & Lock Screen support** for Windows 10/11
- **User or System-Wide modes** - Change wallpaper for just you or all users
- **Group Policy enforcement** - Optional system-wide wallpaper with user restriction
- **Lightweight** - Just two PowerShell scripts (~60KB vs 200MB+ official app)
- **Smart storage** - Configurable image retention and cleanup
- **Zero background processes** - Only runs when scheduled

## Why BWC?

| Feature | Bing Wallpaper Client | Official Bing Wallpaper App |
|---------|----------------------|----------------------------|
| **Size** | ~60 KB ❤️ | 200+ MB 💀 |
| **Background Process** | None 👍 | Always running 👎 |
| **RAM Usage** | 0 MB (when idle) 😉 | 50-100 MB constantly 🤦‍♀️ |
| **Customization** | Full control | Limited |
| **Market** | Changeable | Locked |
| **Multi-User Support** | User or System-wide | Per-user only |
| **Group Policy** | Optional enforcement | No |
| **Command Line** | Yes | No |

## Quick Start

1. Download the installer script from [here](https://github.com/adasThePro/BingWallpaperService/blob/main/installer.ps1) and save it on your desktop.

2. Press `Win + R`, type `powershell`, and press `Enter` to open PowerShell.

3. Navigate to your desktop:
   ```powershell
   cd Desktop
   ```

4. Run the installer script:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\installer.ps1
   ```

## Usage

### Basic Commands

```powershell
# Apply wallpaper immediately
bwc apply

# Check status and configuration
bwc status

# Update configuration
bwc config

# Enable/disable scheduled task
bwc enable
bwc disable

# Show help
bwc help

# Show version
bwc version

# Uninstall completely
bwc uninstall
```

## File Locations

```
C:\Program Files\BingWallpaperClient\
├── BingWallpaperClient.ps1    # Main client script
└── bwc.cmd                     # Command alias wrapper

%APPDATA%\BingWallpaperClient\
├── config.json                 # User configuration
└── logs\                       # Operation logs (if enabled)
    └── YYYY-MM-DD.log

%USERPROFILE%\Pictures\BingWallpapers\
└── *.jpg                       # Downloaded wallpaper images
```

## Scheduled Task

The installer creates a scheduled task that runs:

- **Daily** at 9:00 AM
- **At user logon**
- **When network connects** (after 1 minute delay)

This ensures your wallpaper stays fresh without manual intervention.

### Manual Task Management

```powershell
# Disable task
bwc disable

# Enable task
bwc enable
```

## Uninstallation

To completely remove Bing Wallpaper Client from your system, run the following command in PowerShell:

```powershell
bwc uninstall
```

This will:
- Remove the scheduled task
- Delete client files
- Remove configuration
- Remove from system PATH
- **Preserve** downloaded wallpaper images if you wish to keep them.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.