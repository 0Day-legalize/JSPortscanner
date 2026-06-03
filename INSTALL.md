# Installation

> Made by **Sebastian Litzenberger** and **Jamie Heyckendorf**


## Requirements

- Node.js 18+
- Linux (root/sudo required for raw socket features)
- Arch: `sudo pacman -S base-devel python` for native addon compilation

## Setup

```bash
npm install
```

This installs `raw-socket`, `ssh2`, `basic-ftp` and `axios`.

## Run

```bash
sudo node src/scanner.js --help
```

See `README.md` for the full workflow and all flags.
