# HEX BOT - Telegram Bot

A C++ Telegram bot for Instagram automation with subscription management.

## Quick Start

### Windows
1. Run `quick_build_windows.bat`
2. Executable: `build\Release\hex-bot.exe`

### macOS
1. Run `./quick_build_macos.sh`
2. Executable: `build/hex-bot`

## Configuration

Before running, update these values in `Hex-bot.c++`:
- `BOT_TOKEN`: Your Telegram bot token
- `CONTACT_USERNAME`: Your contact username
- `ADMIN_USER_IDS`: Admin user IDs

## Features

- Subscription management
- Key generation system
- Admin commands
- Instagram session validation
- Multi-platform support

## Admin Commands

- `/addsub <user_id> <days>` - Add subscription
- `/ckey <time>` - Create access key
- `/cpubkey <time>` - Create public trial key
- `/subcount` - Show subscriber count
- `/help_admin` - Show all commands

## Time Format

- `7d` = 7 days
- `24h` = 24 hours
- `30m` = 30 minutes
- `2w` = 2 weeks

## Running

```bash
# macOS/Linux
./build/hex-bot

# Windows
build\Release\hex-bot.exe
```