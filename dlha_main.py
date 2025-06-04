import threading
import logging
from scapy.all import sniff
from flask import Flask, render_template
from flask_socketio import SocketIO
from datetime import datetime

# Initialize Flask app and SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# Attack detection logic (simple rule-based for demonstration)
def detect_attack(packet):
    """
    Enhanced attack detection logic with DoS, Probe, R2L, and U2R attacks
    """
    attack_type = None
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        tcp_flags = packet['TCP'].flags
        
        # DoS Attacks
        if tcp_flags == 2:  
            attack_type = "DoS: SYN Flood Attack"
        elif tcp_flags == 0x3F:  # All flags set
            attack_type = "DoS: TCP Christmas Attack"
        elif packet.haslayer('TCP') and len(packet) > 1000:
            attack_type = "DoS: TCP Buffer Overflow"
            
        # Probe Attacks
        elif tcp_flags == 0x14:
            attack_type = "Probe: Port Scan"
        elif tcp_flags == 0x01:
            attack_type = "Probe: FIN Scan"
        elif tcp_flags == 0x29:
            attack_type = "Probe: XMAS Scan"
        elif tcp_flags == 0x00:
            attack_type = "Probe: NULL Scan"
            
        # R2L (Remote to Local) Attacks
        elif tcp_flags == 0x02 and hasattr(packet, 'dport') and packet.dport == 23:
            attack_type = "R2L: Telnet Brute Force"
        elif tcp_flags == 0x02 and hasattr(packet, 'dport') and packet.dport == 22:
            attack_type = "R2L: SSH Brute Force"
        elif packet.haslayer('TCP') and hasattr(packet, 'dport') and packet.dport == 445:
            attack_type = "R2L: SMB Attack"
            
        # U2R (User to Root) Attacks
        elif packet.haslayer('Raw'):
            try:
                payload = packet['Raw'].load
                payload_str = payload.decode('utf-8', errors='ignore').lower()
                if 'sudo' in payload_str:
                    attack_type = "U2R: Privilege Escalation Attempt"
                elif 'buffer overflow' in payload_str:
                    attack_type = "U2R: Buffer Overflow Attack"
            except:
                pass
            
    # Additional DoS Attacks
    elif packet.haslayer('ICMP'):
        if len(packet) > 1000:
            attack_type = "DoS: ICMP Flood"
    elif packet.haslayer('UDP'):
        if len(packet) > 1000:
            attack_type = "DoS: UDP Flood"
    elif packet.haslayer('DNS'):
        if packet.haslayer('DNSQR') and hasattr(packet, 'qr') and packet.qr == 0:
            if packet.haslayer('UDP') and len(packet) > 512:
                attack_type = "DoS: DNS Amplification"
    
    return attack_type

def process_packet(packet):
    """ Process the packet and detect attacks. """
    try:
        attack_type = detect_attack(packet)
        
        packet_info = {
            'status': "Attack" if attack_type else "Normal",
            'packet_summary': str(packet.summary()),
            'source_ip': packet['IP'].src if packet.haslayer('IP') else "Unknown",
            'dest_ip': packet['IP'].dst if packet.haslayer('IP') else "Unknown",
            'attack_type': attack_type,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Send result to the webpage via SocketIO
        socketio.emit('packet_info', packet_info)
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")
        # Continue monitoring even if one packet fails
        pass

def capture_packets():
    """Capture packets from the network interface."""
    try:
        # Add filter to capture only IP packets
        sniff(iface="Wi-Fi", filter="ip", prn=process_packet, store=0)
    except Exception as e:
        error_msg = f"Error capturing packets: {str(e)}"
        print(error_msg)
        socketio.emit('error', {'message': error_msg})

def start_packet_capture():
    """Start the packet capture process."""
    capture_packets()

# Webpage route
@app.route('/')
def index():
    """ Serve the main webpage. """ 
    return render_template('index.html')

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Start packet capture in a background thread
    packet_capture_thread = threading.Thread(target=start_packet_capture)
    packet_capture_thread.daemon = True
    packet_capture_thread.start()

    # Start the Flask web server with SocketIO
    socketio.run(app, 
                debug=True,
                host='127.0.0.1',
                port=5000,
                allow_unsafe_werkzeug=True)