Web Honeypot – Detect and Log Unauthorized Login Attempts

Overview

This project is a web-based honeypot designed to detect and log unauthorized login attempts on a fake login page and admin panel. It captures attacker details such as IP address, username, password, and user-agent, logs the information, blacklists repeat offenders, and sends email alerts.

Features

✅ Fake Login & Admin Panel – Traps brute-force attackers.
✅ Logging System – Records all login attempts in honeypot.log.
✅ IP Blacklisting – Blocks IPs after 5 failed login attempts.
✅ Email Alerts – Sends notifications for admin login attempts.
✅ User-Agent Tracking – Identifies attacker devices and browsers.


Installation

1. Clone the Repository

git clone https://github.com/rakire/web-honeypot.git
cd web-honeypot

2. Install Dependencies

pip install flask flask-limiter requests

3. Run the Honeypot

python3 honeypot.py

4. Access the Web Interface

Login Page: http://127.0.0.1:8080/

Fake Admin Panel: http://127.0.0.1:8080/admin

Configuration

SMTP Email Alerts

Edit honeypot.py and update these lines with your credentials:

SENDER_EMAIL = "your-email@gmail.com"
SENDER_PASSWORD = "your-app-password"
RECEIVER_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.gmail.com"

⚠️ Use an App Password instead of your real password for security.


Usage & Logging

Check Captured Login Attempts

cat honeypot.log

View Blacklisted IPs

cat blacklist.txt

Track Failed Attempts

cat failed_attempts.txt

Security Features

🔹 Rate Limiting – Prevents rapid brute-force attacks.
🔹 Fake Error Messages – Misleads attackers while logging their actions.
🔹 Geolocation Lookup – Can be extended to track attacker locations.


Future Enhancements

🚀 Database Support (SQLite/MySQL) – Store logs more efficiently.
🚀 Webhook Notifications (Discord/Telegram) – Instant attack alerts.
🚀 AI-Based Attack Pattern Analysis – Detect anomalies in login attempts.


Contributing

Pull requests are welcome! Please open an issue before making major changes.

License

MIT License – Free to use and modify.

Acknowledgments

Flask – Lightweight web framework.

Flask-Limiter – Rate limiting for Flask.

Python SMTP – Email sending module.

📌 Screenshots 
    * USE PDF
 



