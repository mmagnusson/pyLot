# pyLot

A lightweight network traffic analyzer for industrial control systems (ICS) protocols.

## Features

- Upload and analyze PCAP files
- Detect industrial protocols (Modbus, DNP3, BACnet)
- Visualize network topology
- Real-time packet capture (requires TShark)

## Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install TShark (for live capture):**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install tshark
   
   # CentOS/RHEL
   sudo yum install wireshark-cli
   
   # macOS
   brew install wireshark
   ```

3. **Set up permissions for live capture (optional):**
   ```bash
   # Allow non-root capture through dumpcap (answer "Yes"), then join the wireshark group
   sudo dpkg-reconfigure wireshark-common
   sudo usermod -a -G wireshark $USER   # log out and back in afterwards
   ```
   Don't run pyLot itself with `sudo`. dumpcap is the only part that needs capture privileges.

## Usage

1. **Start the application:**
   ```bash
   python app.py                              # serves http://127.0.0.1:5000
   python app.py --capture-interface enp3s0   # also capture live traffic (off by default)
   python app.py --debug                      # Flask debugger and auto-reload, local use only
   ```
   Run `python app.py --help` for all options.

2. **Access the web interface:**
   - Open http://127.0.0.1:5000 in your browser
   - Upload a PCAP or PCAPNG file for analysis
   - View the network topology visualization

Uploads and live capture share one result set: each upload replaces everything stored, including
devices found by live capture. Separate sessions are planned.

## Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `PYLOT_MAX_UPLOAD_MB` | `500` | Largest capture file accepted |
| `PYLOT_TRUSTED_HOSTS` | `localhost,127.0.0.1` | Host names the app answers to; other `Host` headers get a 400 |

## Security

pyLot has no authentication, so by default it only listens on 127.0.0.1. If you pass `--host` to
listen elsewhere, anyone who can reach that address can use it; set `PYLOT_TRUSTED_HOSTS` to the
names you'll browse to it by. Uploaded files are stored under random names, non-capture files are
rejected, and POSTs from other sites are refused.

## Database

The application uses SQLite to store:
- **devices**: IP addresses and device information
- **connections**: Network connections between devices

The database is automatically created on first run.

## Troubleshooting

- **TShark not found**: Install Wireshark CLI tools
- **Permission denied for live capture**: Add user to wireshark group
- **Upload fails**: The error is shown on the upload page; details are in the server log
- **400 Bad Request when browsing by hostname or IP**: Add that name to `PYLOT_TRUSTED_HOSTS`
- **Large captures are slow**: Parsing runs at roughly 200 packets/second, so a 70,000-packet
  capture takes about six minutes

## Development

The application structure:
- `app.py`: Main Flask application
- `parser/pcap_parser.py`: PCAP file parsing
- `capture/live_capture.py`: Real-time packet capture
- `templates/`: HTML templates
- `uploads/`: Uploaded PCAP files 