from scapy.all import sniff, conf, IP, rdpcap
from scapy.arch.windows import get_windows_if_list
from scapy.layers import inet
from flask import Flask, jsonify
import json
import os
import threading
import time
import numpy as np
from flask_cors import CORS
import socket
import ctypes
import sys
import pyshark

app = Flask(__name__)
CORS(app)

# Global variable to store latest results
current_results = {
    'status': 'Normal',
    'confidence': 0.0,
    'packet_count': 0,
    'packets_analyzed': []
}

def extract_features(packet):
    if IP in packet:
        try:
            return {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'proto': packet[IP].proto,
                'len': len(packet),
                'ttl': packet[IP].ttl,
                'timestamp': time.time()
            }
        except Exception as e:
            print(f"Feature extraction error: {str(e)}")
    return None

def analyze_packet(features):
    if features:
        try:
            # Enhanced traffic analysis
            current_count = current_results['packet_count'] + 1
            
            # Check for potential suspicious patterns
            if features['proto'] == 6:  # TCP
                if features['len'] < 60:  # Potential scan
                    return {
                        'status': 'Alert',
                        'confidence': 0.90,
                        'packet_count': current_count,
                        'last_src': features['src'],
                        'last_dst': features['dst'],
                        'alert': 'Potential port scan detected'
                    }
            
            # Normal traffic
            return {
                'status': 'Normal',
                'confidence': 0.95,
                'packet_count': current_count,
                'last_src': features['src'],
                'last_dst': features['dst']
            }
        except Exception as e:
            print(f"Analysis error: {str(e)}")
    return current_results

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

from scapy.all import sniff, conf, IP
import subprocess
import threading
import time

def start_capture():
    if not is_admin():
        print("Error: This script must be run as administrator!")
        sys.exit(1)
        
    try:
        print("Starting live packet capture...")
        # Get list of all network interfaces
        capture = pyshark.LiveCapture()
        interfaces = capture.interfaces
        print(f"Available interfaces: {interfaces}")
        
        # Try each interface until one works
        for interface in interfaces:
            try:
                print(f"Attempting capture on interface: {interface}")
                capture = pyshark.LiveCapture(interface=interface)
                
                # Start capturing packets
                for packet in capture.sniff_continuously():
                    if hasattr(packet, 'ip'):
                        features = {
                            'src': packet.ip.src,
                            'dst': packet.ip.dst,
                            'proto': int(packet.ip.proto),
                            'len': int(packet.length),
                            'ttl': int(packet.ip.ttl),
                            'timestamp': time.time()
                        }
                        result = analyze_packet(features)
                        global current_results
                        current_results.update({
                            'status': result.get('status', 'Normal'),
                            'confidence': result.get('confidence', 0.0),
                            'packet_count': result.get('packet_count', current_results['packet_count'] + 1),
                            'last_src': features['src'],
                            'last_dst': features['dst']
                        })
                        print(f"Packet captured: {features['src']} -> {features['dst']}")
            except Exception as e:
                print(f"Failed to capture on interface {interface}: {str(e)}")
                continue
                    
    except Exception as e:
        print(f"Error in capture: {str(e)}")
        print("Please ensure Wireshark is installed correctly")
        time.sleep(1)

def process_packet(packet):
    try:
        if IP in packet:
            features = extract_features(packet)
            if features:
                result = analyze_packet(features)
                global current_results
                current_results.update({
                    'status': result.get('status', 'Normal'),
                    'confidence': result.get('confidence', 0.0),
                    'packet_count': result.get('packet_count', current_results['packet_count'] + 1),
                    'last_src': features['src'],
                    'last_dst': features['dst']
                })
                print(f"Packet captured: {features['src']} -> {features['dst']}")
    except Exception as e:
        print(f"Error in process_packet: {str(e)}")

# Update the index page to show more information
@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>Network Monitor</title>
            <meta http-equiv="refresh" content="1">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
                .normal { background-color: #dff0d8; }
                .alert { background-color: #f2dede; }
                .details { margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>Network Monitor Status</h1>
            <div id="status-div" class="status normal">
                <p>Status: <span id="status">Loading...</span></p>
                <p>Confidence: <span id="confidence">0</span>%</p>
                <p>Packets Analyzed: <span id="packets">0</span></p>
                <div class="details">
                    <p>Last Source: <span id="last-src">-</span></p>
                    <p>Last Destination: <span id="last-dst">-</span></p>
                </div>
            </div>
            <script>
                function updateStatus() {
                    fetch('/get_status')
                        .then(response => response.json())
                        .then(data => {
                            document.getElementById('status').textContent = data.status;
                            document.getElementById('confidence').textContent = 
                                (data.confidence * 100).toFixed(2);
                            document.getElementById('packets').textContent = data.packet_count;
                            document.getElementById('last-src').textContent = data.last_src || '-';
                            document.getElementById('last-dst').textContent = data.last_dst || '-';
                            
                            const statusDiv = document.getElementById('status-div');
                            statusDiv.className = 'status ' + 
                                (data.status === 'Normal' ? 'normal' : 'alert');
                        });
                }
                setInterval(updateStatus, 1000);
                updateStatus();
            </script>
        </body>
    </html>
    """
@app.route('/get_status')
def get_status():
    try:
        return jsonify(current_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
if __name__ == '__main__':
    # Remove Suricata startup
    
    # Start packet capture thread
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.daemon = True
    capture_thread.start()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000)