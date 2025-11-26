import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import time
devices = [
    (8001, "Temp Sensor", "TempSensor-IoT", "2.1.3"),
    (8002, "Smart Camera", "IP-Camera-Hikvision", "3.0.1"), 
    (8003, "Smart Plug", "Tuya-SmartPlug-T10", "1.5.2"),
    (8004, "Motion Sensor", "Xiaomi-Motion-PIR", "2.0.8"),
    (8005, "IoT Hub", "Zigbee-Hub-Pro", "4.2.0"),
    (8022, "SSH Server", "OpenSSH-IoT", "8.2p1")
]
class IoTHandler(BaseHTTPRequestHandler):
    server_version = "Custom-IoT/1.0"
    
    def do_GET(self):
        response = f"{self.server.device_type} {self.server.version}"
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Server', f'{self.server.device_type}/{self.server.version}')
        self.end_headers()
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        pass
def start_device(port, name, dev_type, version):
    server = HTTPServer(('0.0.0.0', port), IoTHandler)
    server.device_name = name
    server.device_type = dev_type
    server.version = version
    print(f" {name} - Port {port}")
    server.serve_forever()
def start_ssh_service():
    """Service SSH simulé simple"""
    import socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 8022))
    server.listen(5)
    print(" SSH Server - Port 8022")
    while True:
        client, addr = server.accept()
        client.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        time.sleep(0.1)
        client.close()

print(" Démarrage des devices IoT...")
for port, name, dev_type, version in devices:
    if port == 8022:
        thread = threading.Thread(target=start_ssh_service, daemon=True)
    else:
        thread = threading.Thread(target=start_device, args=(port, name, dev_type, version), daemon=True)
    thread.start()

print("Tous les devices sont actifs!")
print(" Ports: 8001-8005 (HTTP), 8022 (SSH)")
print(" Ctrl+C pour arrêter")

try:
    while True: time.sleep(1)
except KeyboardInterrupt:
    print("\nArrêt des devices")
