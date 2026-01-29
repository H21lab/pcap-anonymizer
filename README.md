# PCAP Anonymizer

A browser-based tool for anonymizing network packet capture (PCAP) files. All processing happens locally in your browser - no data is ever uploaded to any server.

Application is available here: https://www.h21lab.com/applications/pcap-anonymizer

## Features

- **Client-side processing**: Your PCAP files never leave your browser
- **Wireshark filter support**: Filter packets using Wireshark display filter syntax
- **Two anonymization methods**:
  - **SHAKE256 hashing**: Deterministic anonymization with optional salt
  - **Masking**: Replace field values with 0xFF bytes
- **Field-level granularity**: Anonymize specific protocol fields
- **Slice notation support**: Anonymize portions of fields using `field[start:end]` syntax
- **Interactive UI**: View packets and add anonymization rules by clicking on fields

## Usage

1. Open the application in your browser
2. Drag and drop a PCAP file (or click to browse)
3. Use Wireshark filter syntax to filter packets (optional)
4. Configure anonymization rules:
   - Add fields to anonymize (SHAKE256 hash-based replacement)
   - Add fields to mask (replace with 0xFF)
   - Set an optional salt for deterministic hashing
5. Click "Download Anonymized PCAP" to export

### Field Notation

Fields use Wireshark field names with `_raw` suffix for raw bytes:
- `ip.src_raw` - Source IP address bytes
- `ip.dst_raw` - Destination IP address bytes
- `eth.src_raw` - Source MAC address bytes
- `sip.from.user_raw` - SIP From user field

Slice notation for partial anonymization:
- `field[0:4]` - First 4 characters (2 bytes in hex)
- `field[-8:]` - Last 8 characters (4 bytes in hex)

## Development

### Prerequisites

- Node.js 16+
- npm

### Installation

```bash
npm install
```

### Running locally

```bash
npm start
```

Opens the application at [http://localhost:3000](http://localhost:3000)

### Building for production

```bash
npm run build
```

The build output will be in the `build/` directory.

## How It Works

1. **Dissection**: PCAP files are parsed and packets are dissected using [Wiregasm](https://github.com/good-tools/wiregasm), a WebAssembly port of Wireshark's dissection engine
2. **Field extraction**: Raw field values are extracted from dissected packets
3. **Anonymization**: Selected fields are either:
   - Hashed using SHAKE256 with optional salt (preserves format)
   - Masked with 0xFF bytes
4. **Reconstruction**: Modified field values are written back to packet frames
5. **Export**: A new PCAP file is generated with anonymized data

## Acknowledgments

This project uses the following open-source components:

- **[Wiregasm](https://github.com/good-tools/wiregasm)** - WebAssembly port of Wireshark dissectors (GPL-2.0)
- **[Wireshark](https://www.wireshark.org/)** - Network protocol analyzer (GPL-2.0)
- **[json2pcap](https://github.com/H21lab/json2pcap)** - PCAP generation utilities (GPL-2.0)
- **[React](https://reactjs.org/)** - UI framework (MIT)
- **[Material-UI](https://mui.com/)** - UI components (MIT)
- **[js-sha3](https://github.com/emn178/js-sha3)** - SHAKE256 implementation (MIT)

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind. The anonymization logic may not be exhaustive for all protocols. Please review your exported PCAPs carefully before sharing or using them in sensitive environments.

## Author

Copyright H21 lab
