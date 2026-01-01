# KAIRO

Lightweight GUI tool for processing Wii U disc images.

## Features

- Convert `.wux` → `.wud`
- Extract `.wud` → WUP format (`code/`, `content/`, `meta/`)
- AES-128-CBC decryption with user-provided keys
- Cross-platform: Windows, Linux, macOS

## Requirements

You must provide your own:
- `common.key` (Wii U common key, 16 bytes)
- Disc/title key (16 bytes, file or hex string)

**Keys are NOT included.**

## Installation

Download the latest release for your platform from [Releases](https://github.com/Zard-Studios/kairo/releases).

## Building from Source

```bash
# Clone
git clone https://github.com/Zard-Studios/kairo.git
cd kairo

# Build
cargo build --release

# Binary at: target/release/kairo
```

## Usage

1. Launch KAIRO
2. Select input file (.wux or .wud)
3. Choose output location
4. Load your keys
5. Click Start

## License

MIT License - See [LICENSE](LICENSE)
