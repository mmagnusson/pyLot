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

3. **Set up permissions for live capture:**
   ```bash
   # Add your user to the wireshark group
   sudo usermod -a -G wireshark $USER
   
   # Or run with sudo (not recommended for production)
   sudo python app.py
   ```

## Usage

1. **Start the application:**
   ```bash
   python app.py
   ```

2. **Access the web interface:**
   - Open http://127.0.0.1:5000 in your browser
   - Upload a PCAP file for analysis
   - View the network topology visualization

## Database

The application uses SQLite to store:
- **devices**: IP addresses and device information
- **connections**: Network connections between devices

The database is automatically created on first run.

## Troubleshooting

- **TShark not found**: Install Wireshark CLI tools
- **Permission denied for live capture**: Add user to wireshark group
- **Upload fails**: Check file format and permissions

## Development

The application structure:
- `app.py`: Main Flask application
- `parser/pcap_parser.py`: PCAP file parsing
- `capture/live_capture.py`: Real-time packet capture
- `templates/`: HTML templates
- `uploads/`: Uploaded PCAP files 