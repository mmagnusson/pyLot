from flask import Flask, render_template, request, redirect, url_for, jsonify
from parser.pcap_parser import parse_pcap
from capture.live_capture import start_live_capture
import os
import sqlite3
from threading import Thread

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('db.sqlite3')
    cur = conn.cursor()
    
    # Create devices table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            vendor TEXT
        )
    ''')
    
    # Create connections table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT NOT NULL,
            dst TEXT NOT NULL,
            protocol TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    try:
        if 'pcap_file' not in request.files:
            return 'No file selected.', 400
        
        file = request.files['pcap_file']
        if file.filename == '':
            return 'No file selected.', 400
        
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(file.filename))
            file.save(filepath)
            
            try:
                devices, connections = parse_pcap(filepath)
                store_results(devices, connections)
                return redirect(url_for('network'))
            except Exception as e:
                return f'Error parsing PCAP file: {str(e)}', 500
        return 'Upload failed.', 400
    except Exception as e:
        return f'Upload error: {str(e)}', 500

@app.route('/network')
def network():
    try:
        conn = sqlite3.connect('db.sqlite3')
        cur = conn.cursor()
        cur.execute("SELECT * FROM devices")
        devices = cur.fetchall()
        cur.execute("SELECT * FROM connections")
        connections = cur.fetchall()
        conn.close()
        return render_template('network.html', devices=devices, connections=connections)
    except Exception as e:
        return f'Database error: {str(e)}', 500

@app.route('/api/graph')
def get_graph():
    try:
        conn = sqlite3.connect('db.sqlite3')
        cur = conn.cursor()
        cur.execute("SELECT src, dst, protocol FROM connections")
        edges = cur.fetchall()
        conn.close()
        return jsonify([{'data': {'source': src, 'target': dst, 'label': proto}} for src, dst, proto in edges])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def store_results(devices, connections):
    try:
        conn = sqlite3.connect('db.sqlite3')
        cur = conn.cursor()
        cur.execute("DELETE FROM devices")
        cur.execute("DELETE FROM connections")
        for d in devices:
            cur.execute("INSERT INTO devices(ip, mac, vendor) VALUES (?, ?, ?)", d)
        for c in connections:
            cur.execute("INSERT INTO connections(src, dst, protocol) VALUES (?, ?, ?)", c)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing results: {e}")

# Start real-time capture in a background thread (only if TShark is available)
try:
    Thread(target=start_live_capture, args=('eth0',), daemon=True).start()
except Exception as e:
    print(f"Warning: Live capture not started - {e}")

if __name__ == '__main__':
    app.run(debug=True)
