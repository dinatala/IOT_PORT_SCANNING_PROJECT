from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import socket
import nmap
import signal
import os
import json
import hashlib
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)

# Configuration de sécurité
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# GESTION DES UTILISATEURS
USERS = {
    'admin': generate_password_hash('admin123'),
}

# CONFIGURATION SCANNER NMAP
NETWORK = "127.0.0.1"

# HISTORIQUE DES SCANS
SCAN_HISTORY = []
LOG_FILE = "scan_logs.json"
HASH_HISTORY_FILE = "hash_history.json"

def check_privileges():
    """Vérifie si le script est exécuté en root"""
    return os.geteuid() == 0

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Veuillez vous connecter pour accéder au dashboard.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def compute_scan_hash(scan_record):
    """Calcule le hash SHA-256 d'un enregistrement de scan"""
    data_string = f"{scan_record['user']}{scan_record['timestamp']}{json.dumps(scan_record['results'], sort_keys=True)}"
    return hashlib.sha256(data_string.encode()).hexdigest()

def save_hash_to_history(scan_record):
    """Sauvegarde le hash dans l'historique JSON"""
    hash_entry = {
        "hash": scan_record["hash"],
        "user": scan_record["user"],
        "timestamp": scan_record["timestamp"],
        "device_count": len(scan_record["results"]),
        "devices": [device["name"] for device in scan_record["results"]]
    }
    
    try:
        # Charger l'historique existant
        if os.path.exists(HASH_HISTORY_FILE):
            with open(HASH_HISTORY_FILE, "r") as f:
                history = json.load(f)
        else:
            history = []
        
        # Ajouter la nouvelle entrée
        history.append(hash_entry)
        
        # Sauvegarder l'historique
        with open(HASH_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=4, ensure_ascii=False)
        
        print(f" Hash sauvegardé dans {HASH_HISTORY_FILE}")
        return True
    except Exception as e:
        print(f"Erreur sauvegarde hash: {e}")
        return False

def load_hash_history():
    """Charge l'historique des hashs"""
    try:
        if os.path.exists(HASH_HISTORY_FILE):
            with open(HASH_HISTORY_FILE, "r") as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f" Erreur chargement historique: {e}")
        return []

def scan_tcp():
    try:
        nm = nmap.PortScanner()
        print(" Scan TCP en cours...")
        nm.scan(hosts=NETWORK, arguments="-p- -T4 --open -sV")
        devices = []
        for host in nm.all_hosts():
            if "tcp" in nm[host]:
                for port, info in nm[host]["tcp"].items():
                    if info["state"] == "open":
                        devices.append({
                            "ip": host, "port": port, "proto": "TCP",
                            "service": info.get("name", "unknown"),
                            "product": info.get("product", ""),
                            "version": info.get("version", "")
                        })
                        print(f"   ✓ TCP {host}:{port} - {info.get('product', info.get('name'))}")
        print(f"   → {len(devices)} device(s) TCP trouvé(s)")
        return devices
    except Exception as e:
        print(f"Erreur TCP: {e}")
        return []

def scan_udp():
    try:
        nm = nmap.PortScanner()
        print(" Scan UDP en cours...")
        nm.scan(hosts=NETWORK, arguments="-sU --top-ports 50 --open -T5 -sV")
        devices = []
        for host in nm.all_hosts():
            if "udp" in nm[host]:
                for port, info in nm[host]["udp"].items():
                    if info["state"] in ["open", "open|filtered"]:
                        devices.append({
                            "ip": host, "port": port, "proto": "UDP",
                            "service": info.get("name", "unknown"),
                            "product": info.get("product", ""),
                            "version": info.get("version", "")
                        })
                        print(f"   ✓ UDP {host}:{port} - {info.get('product', info.get('name'))}")
        print(f"   → {len(devices)} device(s) UDP trouvé(s)")
        return devices
    except Exception as e:
        print(f"Erreur UDP: {e}")
        return []

def fingerprint_device(dev):
    fp = []
    for key in ["service", "product", "version", "os", "hostname"]:
        if dev.get(key):
            fp.append(str(dev[key]))
    if dev.get("cpe"):
        fp.append(dev["cpe"])
    if dev.get("extra_info"):
        fp.append(dev["extra_info"])
    return " | ".join(fp) if fp else "Unknown Device"

def identify_device(dev):
    product = dev.get("product", "").lower()
    service = dev.get("service", "").lower()
    version = dev.get("version", "").lower()
    port = dev.get("port", "")
    
    info = f"{product} {service} {version} {port}".lower()
    
    if port == 8001 or "temperature" in product or "temp_sensor" in info:
        return "Temp Sensor"
    elif port == 8002 or "camera" in product or "ipcam" in info:
        return "Smart Camera"
    elif port == 8003 or "tuya" in product or "smartplug" in info:
        return "Smart Plug"
    elif port == 8004 or "motion" in product or "pir" in info:
        return "Motion Sensor"
    elif port == 8005 or "hub" in product or "zigbee" in info:
        return "IoT Hub"
    elif port == 8022 or "ssh" in service:
        return "SSH Server"
    elif "http" in service and port == 5000:
        return "Web Server"
    elif "http" in service:
        port_mapping = {
            8001: "Temp Sensor",
            8002: "Smart Camera", 
            8003: "Smart Plug",
            8004: "Motion Sensor",
            8005: "IoT Hub",
            8006: "Smart Light",
            8007: "Door Lock",
            8008: "Thermostat"
        }
        return port_mapping.get(port, "Web Server")
    
    if any(x in info for x in ["camera", "ipc", "ipcam", "hikvision", "dahua"]):
        return "Camera"
    if any(x in info for x in ["tuya", "tplink", "smartplug", "plug", "socket"]):
        return "Smart Plug"
    if any(x in info for x in ["sensor", "temperature", "humidity", "motion", "pir"]):
        return "Sensor"
    if any(x in info for x in ["hub", "gateway", "bridge", "zigbee", "zwave"]):
        return "Smart Hub"
    if any(x in info for x in ["router", "openwrt", "netgear", "tp-link"]):
        return "Router"
    if "ssh" in service:
        return "SSH Server"
    if "ftp" in service:
        return "FTP Server"
    if "upnp" in service:
        return "UPnP Device"
    
    return "Unknown IoT Device"

# TEMPLATE LOGIN COMPLET
login_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login - IoT Dashboard Sécurisé</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 420px;
            width: 100%;
            animation: slideUp 0.5s ease;
        }
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .lock-icon {
            font-size: 60px;
            margin-bottom: 15px;
        }
        .login-header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 8px;
        }
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        .alert {
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .alert-danger {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }
        .alert-warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
        }
        .alert-success {
            background: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .login-button {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        .login-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(102, 126, 234, 0.3);
        }
        .login-button:active {
            transform: translateY(0);
        }
        .credentials-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        .credentials-info strong {
            color: #333;
            display: block;
            margin-bottom: 8px;
        }
        .credentials-info code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #495057;
        }
        .security-badge {
            background: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 12px;
            text-align: center;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            
            <h2>Log in </h2>
            
        </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-group">
                <label for="username"> Nom d'utilisateur</label>
                <input type="text" id="username" name="username" required autofocus placeholder="Entrez votre identifiant">
            </div>
            <div class="form-group">
                <label for="password"> Mot de passe</label>
                <input type="password" id="password" name="password" required placeholder="Entrez votre mot de passe">
            </div>
            <button type="submit" class="login-button"> Se connecter</button>
        </form>
        
        
        </div>
        
        
    </div>
</body>
</html>
"""

# TEMPLATE DASHBOARD COMPLET
dashboard_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IoT Dashboard - Scanner Nmap Sécurisé</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            margin: 0;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 2px solid #f0f0f0;
        }
        .header h1 {
            color: #333;
            margin: 0;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .user-badge {
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }
        .logout-button {
            background: #ff6b6b;
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .logout-button:hover {
            background: #ee5a6f;
            transform: translateY(-2px);
        }
        .info {
            text-align: center;
            color: #666;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: #856404;
        }
        .success {
            background: #d4edda;
            border: 1px solid #28a745;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: #155724;
        }
        .info-box {
            background: #d1ecf1;
            border: 1px solid #17a2b8;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: #0c5460;
        }
        .security-banner {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 600;
        }
        .hash-info {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-family: 'Courier New', monospace;
        }
        .hash-label {
            font-weight: bold;
            color: #495057;
            margin-bottom: 5px;
        }
        .hash-value {
            color: #28a745;
            word-break: break-all;
            font-size: 12px;
        }
        .history-info {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: #856404;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            background: #fff; 
            margin-top: 20px;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
        }
        tr:hover { 
            background-color: #f8f9fa; 
        }
        .fingerprint {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-width: 300px;
            word-wrap: break-word;
        }
        .no-devices {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        .badge {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }
        .badge-tcp {
            background: #28a745;
        }
        .badge-udp {
            background: #007bff;
        }
        .stop-button {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
            border: none;
            padding: 10px 25px;
            font-size: 14px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-left: 10px;
        }
        .stop-button:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            transform: translateY(-2px);
        }
        .nmap-badge {
            background: #343a40;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🔍 IoT Devices Dashboard <span class="nmap-badge">Nmap + Hashage</span></h1>
            </div>
            <div class="user-info">
                <span class="user-badge">👤 {{ session.user }}</span>
                <form method="POST" action="{{ url_for('logout') }}" style="margin: 0;">
                    <button type="submit" class="logout-button">Déconnexion</button>
                </form>
                <form method="POST" action="{{ url_for('shutdown') }}" onsubmit="return confirm('Arrêter le serveur ?');" style="margin: 0;">
                    <button type="submit" class="stop-button">Arrêter</button>
                </form>
            </div>
        </div>
        
        {% if scan_hash %}
        <div class="security-banner">
            🔒 Scan sécurisé - Hash SHA-256 généré et sauvegardé
        </div>
        <div class="hash-info">
            <div class="hash-label">Timestamp:</div>
            <div>{{ scan_timestamp }}</div>
            <div class="hash-label" style="margin-top: 10px;">Hash SHA-256:</div>
            <div class="hash-value">{{ scan_hash }}</div>
        </div>
        {% endif %}
        
        {% if total_scans > 0 %}
        <div class="history-info">
            📊 Historique des scans : <strong>{{ total_scans }}</strong> scan(s) sauvegardé(s) dans <code>hash_history.json</code>
        </div>
        {% endif %}
        
        {% if not has_root %}
        <div class="warning">
             <strong>Avertissement :</strong> Ce script nécessite les privilèges root pour utiliser nmap correctement.
            <br><code>sudo python app.py</code>
        </div>
        {% endif %}    
        
        {% if devices|length > 0 %}
        <div class="success">
            <strong>{{ devices|length }}</strong> appareil(s) IoT détecté(s)
        </div>
        <table>
            <tr>
                <th>Device Type</th>
                <th>IP Address</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Fingerprint</th>
            </tr>
            {% for device in devices %}
            <tr>
                <td><strong>{{ device.name }}</strong></td>
                <td>{{ device.ip }}</td>
                <td>{{ device.port }}</td>
                <td><span class="badge badge-{{ device.proto|lower }}">{{ device.proto }}</span></td>
                <td>{{ device.service }}{% if device.version %} {{ device.version }}{% endif %}</td>
                <td class="fingerprint">{{ device.fingerprint }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <div class="no-devices">
            <h2> Aucun appareil IoT détecté.</h2>
            <p style="font-size: 14px; color: #666; margin-top: 20px;"><strong>Vérifications :</strong></p>
            <ol style="text-align: left; display: inline-block; font-size: 13px;">
                <li>Les devices virtuels sont-ils lancés ?</li>
                <li>Le script tourne-t-il avec sudo ? <code>ss -tulpn | grep -E '8000|9000|1900'</code></li>
                <li>Nmap est-il installé ? <code>sudo apt install nmap</code></li>
            </ol>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and check_password_hash(USERS[username], password):
            session['user'] = username
            session.permanent = True
            flash('Connexion réussie !', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants incorrects', 'danger')
    
    return render_template_string(login_template)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Déconnexion réussie', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    has_root = check_privileges()
    real_devices = []
    scan_hash = None
    scan_timestamp = None

    try:
        print(f"\nDashboard accédé par : {session['user']}")
        
        # Scan TCP et UDP
        tcp_results = scan_tcp()
        udp_results = scan_udp()
        all_devices = tcp_results + udp_results

        # Process devices
        for dev in all_devices:
            real_devices.append({
                "name": identify_device(dev),
                "ip": dev["ip"],
                "port": dev["port"],
                "proto": dev["proto"],
                "service": dev["service"],
                "version": dev.get("version", ""),
                "fingerprint": fingerprint_device(dev)
            })

        # Hashage et stockage
        scan_record = {
            "user": session['user'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": real_devices
        }
        
        scan_hash = compute_scan_hash(scan_record)
        scan_record["hash"] = scan_hash
        scan_timestamp = scan_record["timestamp"]

        # Stockage en mémoire
        SCAN_HISTORY.append(scan_record)

        # Stockage en fichier JSON principal
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except FileNotFoundError:
            logs = []

        logs.append(scan_record)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)

        # Sauvegarde dans l'historique des hashs
        save_hash_to_history(scan_record)

        print(f"Scan sauvegardé dans {LOG_FILE}")
        print(f"Hash du scan : {scan_hash}")

    except Exception as err:
        print(f"Erreur dashboard : {err}")
        flash('Erreur pendant le scan', 'danger')

    # Charger l'historique des scans pour afficher le compte
    hash_history = load_hash_history()
    total_scans = len(hash_history)

    return render_template_string(
        dashboard_template, 
        devices=real_devices,
        network=NETWORK,
        has_root=has_root,
        session=session,
        scan_hash=scan_hash,
        scan_timestamp=scan_timestamp,
        total_scans=total_scans
    )

@app.route("/shutdown", methods=["POST"])
@login_required
def shutdown():
    os.kill(os.getpid(), signal.SIGINT)
    return "Serveur en cours d'arrêt..."

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" IoT Dashboard avec Nmap et Authentification")
    print("="*60)
    
    try:
        nm = nmap.PortScanner()
        print("Nmap détecté et fonctionnel")
    except:
        print(" ERREUR : Nmap n'est pas installé !")
        print("   Installez-le avec : sudo apt install nmap python3-nmap")
        exit(1)
        
    if not check_privileges():
        print("  AVERTISSEMENT : Script non exécuté en root !")
        print("   Le scan nmap nécessite des privilèges root.")
        print("   Utilisez : sudo python app.py")
    else:
        print(" Privilèges root détectés")
        
    print("Sign in")
    print(" Scanner : localhost (127.0.0.1)")
    app.run(host="0.0.0.0", port=5000, debug=True)
