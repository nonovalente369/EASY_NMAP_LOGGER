import socket
import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf

# CONFIG
WATCH_RANGE     = range(7500, 8501)     # Change port-range based on custom needs
MY_IP           = "0.0.0.0"             # Change to your server's IP
HONEYPOT_PORT   = 8000                  # Change to custom honeypot (bait) port
conf.verb       = 0                     # Keeps Scapy's internal technical chatter hidden --> Using only our own print statements

# STATE TRACKING
history     = {}                    # Recording dictionary for each attacked port
memory_lock = threading.Lock()      # Ensures threads don't collapse

# LOGGER
def log_event(category, ip, port, details=""):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"\nTime: {now}\nWARNING: {category}\nAttacker's IP: {ip}\nAttacked Port: {port}")     
    if details:
        print(f"Details: {details}")
    print("------------------------------")

# ANALYSIS
def protocol_recognizer():
    while True:
        time.sleep(10)              # Let CPU sleep, so not overload
        with memory_lock:           # Using threading to make sure no collisions happen
            now = time.time()
            scan_end = []           # To add finished scans
            
            for attacker_ip, info in history.items():   # Check each recorded IP
                if now - info['last_seen'] > 3.0:       # If attacker no longer active for 3 seconds
                    
                    if info['tcp_ports']:                                       # Check if any TCP ports were hit via TCP packets
                        tcp_ports       = sorted(list(info['tcp_ports']))       # Sort all ports
                        tcp_length      = len(tcp_ports)                        # Length of all ports
                        min_tcp         = tcp_ports[0]                          # Minimum port number
                        max_tcp         = tcp_ports[-1]                         # Maximum port number
                        tcp_range       = f"{min_tcp} - {max_tcp}"              # Range of ports

                        if tcp_length > 1:
                            log_event("TCP MULTIPLE PORT SCAN", attacker_ip, 
                                      tcp_range, f"Hit {tcp_length} unique ports.")  # Call logger & add details if multiple ports
                        else:
                            log_event("TCP SINGLE PORT SCAN", attacker_ip, 
                                      min_tcp, f"Hit {min_tcp} port.")                # Call logger and add details if single ports

                    # Same logic as above for TCP, but for UDP
                    if info['udp_ports']:                           
                        udp_ports       = sorted(list(info['udp_ports']))
                        udp_length      = len(udp_ports)
                        min_udp         = udp_ports[0]
                        max_udp         = udp_ports[-1]
                        udp_range       = f"{min_udp} - {max_udp}"

                        if udp_length > 1:
                            log_event("UDP MULTIPLE PORT SCAN", attacker_ip, 
                                      udp_range, f"Hit {udp_length} UDP ports")
                        else:
                            log_event("UDP SINGLE PORT SCAN", attacker_ip, 
                                      min_udp, f"Hit {min_udp} port.")
                    scan_end.append(attacker_ip)
            
            for ip in scan_end:         # Checking IP when finished scans
                del history[ip]         # Remove from history to free memory & prevent CPU Lag

# PACKET WATCHDOG / GUARD
def watchdog():
    print(f"Monitoring started: Monitoring ports {WATCH_RANGE.start} to {WATCH_RANGE.stop-1}")

    def inspect_packet(packet):
        # Packet types
        ip_data     = packet.haslayer(IP)
        tcp_data    = packet.haslayer(TCP)
        raw_data    = packet.haslayer(Raw)
        udp_data    = packet.haslayer(UDP)
        icmp_data   = packet.haslayer(ICMP)

        if not ip_data:
            return                                 
        
        attacker_ip = packet[IP].src      # Get IP source address
        curr_time   = time.time()
        
        with memory_lock:
            if attacker_ip not in history:
                history[attacker_ip] = {
                "tcp_ports": set(), 
                "udp_ports": set(), 
                "last_seen": 0
            }                               # Init an entry for new attacker
        
        # LAYER 4 - Transport Layer
        # TCP
        if tcp_data:
            target_tcp  = packet[TCP].dport     # Extract target port (which port attacker are hitting)
            tcp_flags   = packet[TCP].flags     # Extract TCP flags ( = what sort of signal)
            
            if target_tcp in WATCH_RANGE:
                with memory_lock:            
                    history[attacker_ip]["tcp_ports"].add(target_tcp)   # Record TCP ports being hit, if unique
                    history[attacker_ip]["last_seen"] = time.time()     # Update timestamp of last attack

                # Check for different scan patterns
                if tcp_flags == 0 or tcp_flags == "": 
                    log_event("NULL SCAN (-sN)", attacker_ip, target_tcp, 
                              "TCP packet with no flags")
                
                # Bypass simple firewalls
                elif tcp_flags == "FPU":
                    log_event("XMAS SCAN (-sX)", attacker_ip, target_tcp, 
                              "Flags: FIN, PUSH, URG")
                
                # Attacker find open ports silently
                elif tcp_flags == "F":
                    log_event("FIN SCAN (-sF)", attacker_ip, target_tcp, 
                              "Closing a non-existent connection")
                
                # LAYER 7 - Application Layer
                if raw_data:
                    try:
                        content = packet[Raw].load.decode(errors='ignore')              # Decode raw (binary) payload, ignore random binaries
                        if "GET" in content or "HTTP" in content or "SSH" in content:   # Search for keywords in payload
                            preview = content[:20].strip()
                            log_event("VERSION PROBE (-sV)", attacker_ip, target_tcp, 
                                      f"Found Layer 7 data: {preview}...")
                    except:
                        pass
        
        # LAYER 4 - Transport Layer
        # UDP
        elif udp_data:
            target_udp = packet[UDP].dport
            if target_udp in WATCH_RANGE:
                with memory_lock:
                    history[attacker_ip]["udp_ports"].add(packet[UDP].dport)
                    history[attacker_ip]["last_seen"] = curr_time          

        # LAYER 3 - Network Layer
        # ICMP
        elif icmp_data:
            icmp_type = packet[ICMP].type
            if icmp_type == 8:                                                          
                log_event("ICMP DISCOVERY (-sn)", attacker_ip, 
                          "N/A", "Ping request detected")
    
    # Scrapy try to capture all packets on network interface
    sniff(prn=inspect_packet, store=0)              

# TRAP (HONEYPOT)
def port_trap():
    trap_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # Create TCP socket, using IPv4
    trap_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # Allows us to restart directly with same port
    
    try:
        trap_socket.bind((MY_IP, HONEYPOT_PORT))    # Bind all traffic to honeypot port
        trap_socket.listen(5)                       # Listen for incoming connections
        print(f"Trap set: Waiting... {HONEYPOT_PORT}")

        while True:
            visitor, address = trap_socket.accept()    # Accept incoming connection
            address = address[0]
            visitor.settimeout(0.1)
            
            try:
                # Captures 'Service Version' text NMAP sends
                message = visitor.recv(1024).decode(errors='ignore')
                
                # Attacker sent something, save information in log 
                if message:
                    log_event("SERVICE FINGERPRINTING", address, 
                              HONEYPOT_PORT, f"Client sent: {message.strip()}")
                
                # No message, still save log connection
                else:
                    log_event("TCP CONNECT (-sT)", address, 
                              HONEYPOT_PORT, "Completed handshake, sent no data.")    
            
            # Attacker doesn't send anything within time-period save silent connection
            except socket.timeout:
                log_event("SILENT CONNECTION", address, 
                          HONEYPOT_PORT, "Handshake completed, but timed out waiting for data.")
            
            # Finally close connection
            finally:
                visitor.close() 
    
    # Handle any unexpected errors such as network issues, permission errors, etc.
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("------------------------------")
    print("NETWORK ATTACK ANALYZER")
    print("------------------------------")
    
    # Run all three sections at same time
    threading.Thread(target=protocol_recognizer, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=port_trap, daemon=True).start()
    
    try:
        while True: 
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down monitor!")