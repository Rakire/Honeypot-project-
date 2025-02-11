from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import smtplib
from email.mime.text import MIMEText
import requests

app = Flask(__name__)

# Flask-Limiter for rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

LOG_FILE = "honeypot.log"
BLACKLIST_FILE = "blacklist.txt"

# Gmail SMTP Configuration
ALERT_EMAIL = "receiver@gmail.com"  # Receiver email
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "sender@gmail.com"  # Sender email
SMTP_PASS = "112233"  # Sender password (not recommended to hardcode)

def log_attempt(ip, username, password, user_agent, endpoint):
    """Logs attack details to a file."""
    country = get_geo_info(ip)
    log_entry = f"[{endpoint}] IP: {ip} (Country: {country}), Username: {username}, Password: {password}, User-Agent: {user_agent}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    
    # Send alert if it's an admin login attempt
    if endpoint == "ADMIN":
        send_alert(ip, username, password, endpoint)

    # Check for repeated login attempts
    track_failed_attempts(ip)

def track_failed_attempts(ip):
    """Track failed attempts and blacklist after 5 failures."""
    attack_count = {}
    try:
        with open("failed_attempts.txt", "r") as f:
            attack_count = eval(f.read())
    except FileNotFoundError:
        pass
    
    attack_count[ip] = attack_count.get(ip, 0) + 1
    
    # Blacklist if the attempts exceed 5
    if attack_count[ip] >= 5:
        blacklist_ip(ip)
    
    with open("failed_attempts.txt", "w") as f:
        f.write(str(attack_count))

def is_blacklisted(ip):
    """Check if an IP is blacklisted."""
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklisted_ips = f.read().splitlines()
        return ip in blacklisted_ips
    except FileNotFoundError:
        return False

def blacklist_ip(ip):
    """Blacklist an IP after multiple failed attempts."""
    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{ip}\n")

def send_alert(ip, username, password, endpoint):
    """Send an alert email."""
    msg = MIMEText(f"Attack detected on {endpoint}\nIP: {ip}\nUsername: {username}\nPassword: {password}")
    msg["Subject"] = "Honeypot Alert"
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
    except Exception as e:
        print(f"Failed to send email: {e}")

def get_geo_info(ip):
    """Fetch geolocation of IP."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json().get("country", "Unknown")
    except:
        return "Unknown"

@app.route("/")
def home():
    return '''
        <h1>Welcome to Secure Login</h1>
        <form action='/login' method='post'>
            <input type='text' name='username' placeholder='Username'><br>
            <input type='password' name='password' placeholder='Password'><br>
            <input type='submit' value='Login'>
        </form>
    '''

@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute")
def capture_login():
    """Captures login attempts and logs details."""
    ip = request.remote_addr
    if is_blacklisted(ip):
        return "<h1>Access Denied</h1>", 403

    username = request.form.get("username")
    password = request.form.get("password")
    user_agent = request.headers.get("User-Agent")

    log_attempt(ip, username, password, user_agent, "LOGIN")
    return "<h1>Login Failed</h1>"

@app.route("/admin")
def fake_admin():
    """Fake admin panel to attract bots."""
    return '''
        <h1>Admin Panel</h1>
        <form action='/admin/login' method='post'>
            <input type='text' name='admin_user' placeholder='Admin Username'><br>
            <input type='password' name='admin_pass' placeholder='Admin Password'><br>
            <input type='submit' value='Login'>
        </form>
        <p>Download the latest Admin Panel software <a href='/admin/download'>here</a></p>
    '''

@app.route("/admin/login", methods=["POST"])
@limiter.limit("2 per minute")
def capture_admin_login():
    """Captures login attempts on the fake admin panel."""
    ip = request.remote_addr
    if is_blacklisted(ip):
        return "<h1>Access Denied</h1>", 403

    username = request.form.get("admin_user")
    password = request.form.get("admin_pass")
    user_agent = request.headers.get("User-Agent")

    log_attempt(ip, username, password, user_agent, "ADMIN")
    return "<h1>Access Denied</h1>"

@app.route("/admin/download")
def fake_download():
    """Fake admin panel software download to track bots."""
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    log_attempt(ip, "N/A", "N/A", user_agent, "FAKE_DOWNLOAD")
    return "<h1>404 Not Found</h1>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
