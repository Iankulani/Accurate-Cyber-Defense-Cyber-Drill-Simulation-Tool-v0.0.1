"""
🚀 ACCURATE CYBER DEFDENSE CYBER DRILL SIMULATION 
Author: Ian Carter Kulani 
Version: 1.0.0


import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import shutil
import uuid
import base64
import csv
import getpass

# Color for terminal (optional)
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class FakeColors:
        def __getattr__(self, name):
            return ''
    Fore = Back = Style = FakeColors()

# Try to import nmap for scanning
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ============================
# CONFIGURATION
# ============================
CONFIG_FILE = "accurateos_config.json"
TELEGRAM_CONFIG_FILE = "telegram_config.json"
LOG_FILE = "accurateos.log"
DATABASE_FILE = "accurateos.db"
REPORT_DIR = "reports"
COMMAND_HISTORY_FILE = "command_history.json"
TEMPLATES_DIR = "templates"
SCANS_DIR = "scans"
ALERTS_DIR = "alerts"

# Create directories
for directory in [REPORT_DIR, TEMPLATES_DIR, SCANS_DIR, ALERTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("AccurateOS")

# ============================
# DATA CLASSES
# ============================
@dataclass
class ThreatAlert:
    """Threat alert data class"""
    id: str
    timestamp: str
    threat_type: str
    source_ip: str
    target_ip: str
    severity: str
    description: str
    action_taken: str
    resolved: bool

@dataclass
class ScanResult:
    """Scan result data class"""
    id: str
    timestamp: str
    target: str
    scan_type: str
    ports: List[int]
    services: Dict
    vulnerabilities: List[str]
    risk_level: str

# ============================
# ENHANCED TRACEROUTE TOOL
# ============================
class TracerouteTool:
    """Enhanced interactive traceroute tool with geolocation and visualization"""
    
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.geolocation_cache = {}
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))
    
    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()
        
        if system == 'Windows':
            return ['tracert', '-d', target]
        
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', '-m', '30', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]
        
        raise EnvironmentError('No traceroute utilities found on this system.')
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation for IP address"""
        if ip in self.geolocation_cache:
            return self.geolocation_cache[ip]
        
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    self.geolocation_cache[ip] = data
                    return data
        except:
            pass
        
        return {
            'country': 'Unknown',
            'regionName': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'lat': 0,
            'lon': 0
        }
    
    def stream_subprocess(self, cmd: List[str]) -> Tuple[int, str, List[Dict]]:
        """Run subprocess and capture output with hop analysis"""
        output_lines = []
        hops = []
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    
                    # Parse traceroute output for hops
                    hop_match = re.match(r'\s*(\d+)\s+([\d\.]+|[\w:]+)\s+', cleaned_line)
                    if hop_match:
                        hop_num = int(hop_match.group(1))
                        hop_ip = hop_match.group(2)
                        
                        if self.is_ipv4_or_ipv6(hop_ip):
                            geo = self.get_geolocation(hop_ip)
                            hops.append({
                                'hop': hop_num,
                                'ip': hop_ip,
                                'country': geo.get('country', 'Unknown'),
                                'isp': geo.get('isp', 'Unknown'),
                                'latency': self._extract_latency(cleaned_line)
                            })
                    
                    print(cleaned_line)
            
            proc.wait()
            return proc.returncode, '\n'.join(output_lines), hops
            
        except KeyboardInterrupt:
            print('\n[+] User cancelled. Terminating traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines), hops
        except Exception as e:
            error_msg = f'[!] Error running command: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines), hops
    
    def _extract_latency(self, line: str) -> str:
        """Extract latency from traceroute output"""
        patterns = [
            r'(\d+\.\d+)\s*ms',
            r'(\d+)\s*ms',
            r'<\d+\s*ms',
            r'\*\s*\*\s*\*'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        
        return "N/A"
    
    def interactive_traceroute(self, target: str = None, advanced: bool = False) -> str:
        """Run interactive traceroute with enhanced features"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"
        
        try:
            if advanced:
                cmd = self._choose_advanced_traceroute(target)
            else:
                cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"
        
        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output, hops = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time
        
        # Generate enhanced report
        result = self._generate_enhanced_report(target, cmd, output, execution_time, returncode, hops)
        
        return result
    
    def _choose_advanced_traceroute(self, target: str) -> List[str]:
        """Choose advanced traceroute command based on available tools"""
        if platform.system() == 'Windows':
            return ['tracert', '-d', '-h', '30', '-w', '1000', target]
        
        if shutil.which('mtr'):
            return ['mtr', '--report', '--report-wide', '--no-dns', target]
        elif shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '3', '-w', '3', '-m', '40', '-z', '100', target]
        else:
            return self.choose_traceroute_cmd(target)
    
    def _generate_enhanced_report(self, target: str, cmd: List[str], output: str, 
                                 execution_time: float, returncode: int, 
                                 hops: List[Dict]) -> str:
        """Generate enhanced traceroute report"""
        result = f"🚀 <b>ENHANCED TRACEROUTE REPORT</b>\n\n"
        result += f"📌 Target: <code>{target}</code>\n"
        result += f"🔧 Command: <code>{' '.join(cmd)}</code>\n"
        result += f"⏱️ Execution Time: {execution_time:.2f}s\n"
        result += f"📊 Return Code: {returncode}\n\n"
        
        if hops:
            result += f"🌍 <b>GEOGRAPHICAL ANALYSIS</b>\n"
            result += f"Hops: {len(hops)}\n\n"
            
            # Group by country
            countries = {}
            for hop in hops:
                country = hop['country']
                if country not in countries:
                    countries[country] = []
                countries[country].append(hop)
            
            for country, country_hops in countries.items():
                result += f"📍 {country}: {len(country_hops)} hops\n"
            
            result += "\n"
            
            # Show first 10 hops with details
            result += f"🛣️ <b>FIRST 10 HOPS</b>\n"
            for hop in hops[:10]:
                result += f"{hop['hop']:2d}. {hop['ip']:15s} | {hop['country']:15s} | {hop['latency']}\n"
            
            if len(hops) > 10:
                result += f"... and {len(hops) - 10} more hops\n\n"
        
        # Add raw output (limited)
        if len(output) > 2000:
            result += f"📄 <b>RAW OUTPUT (LAST 2000 CHARS)</b>\n<code>{output[-2000:]}</code>"
        else:
            result += f"📄 <b>RAW OUTPUT</b>\n<code>{output}</code>"
        
        return result
    
    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP address or hostname to traceroute (or type "quit" to exit): ').strip()
            if not user_input:
                print('Please enter a non-empty value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None
            
            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com')

# ============================
# DATABASE MANAGER
# ============================
class DatabaseManager:
    """Enhanced database manager for comprehensive logging"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize all database tables"""
        tables = [
            # Threats table
            '''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_ip TEXT,
                severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0,
                resolved_at DATETIME,
                metadata TEXT
            )
            ''',
            # Commands history
            '''
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                user TEXT
            )
            ''',
            # Scan results
            '''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                risk_level TEXT,
                raw_output TEXT,
                duration REAL
            )
            ''',
            # Network connections
            '''
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                protocol TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT,
                process_name TEXT,
                process_id INTEGER,
                country TEXT,
                asn TEXT
            )
            ''',
            # Traceroute results
            '''
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                hops INTEGER,
                success BOOLEAN DEFAULT 1
            )
            ''',
            # Monitored IPs
            '''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id TEXT PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                notes TEXT,
                tags TEXT
            )
            ''',
            # Command templates
            '''
            CREATE TABLE IF NOT EXISTS command_templates (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                command TEXT NOT NULL,
                description TEXT,
                parameters TEXT,
                usage_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''',
            # System metrics
            '''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent REAL,
                network_recv REAL,
                connections_count INTEGER,
                processes_count INTEGER
            )
            '''
        ]
        
        for table_sql in tables:
            try:
                self.cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Error creating table: {e}")
        
        self.conn.commit()
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat to database"""
        try:
            self.cursor.execute('''
                INSERT INTO threats 
                (id, timestamp, threat_type, source_ip, target_ip, severity, description, action_taken, resolved, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.id, alert.timestamp, alert.threat_type, alert.source_ip, 
                alert.target_ip, alert.severity, alert.description, 
                alert.action_taken, alert.resolved, json.dumps(asdict(alert))
            ))
            self.conn.commit()
            
            # Log to file as well
            alert_file = os.path.join(ALERTS_DIR, f"alert_{alert.id}.json")
            with open(alert_file, 'w') as f:
                json.dump(asdict(alert), f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_command(self, command: str, source: str = "local", success: bool = True, 
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            command_id = str(uuid.uuid4())
            user = getpass.getuser()
            
            self.cursor.execute('''
                INSERT INTO commands 
                (id, command, source, success, output, execution_time, user)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (command_id, command, source, success, output[:5000], execution_time, user))
            self.conn.commit()
            
            return command_id
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
            return None
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            self.cursor.execute('''
                INSERT INTO scans 
                (id, timestamp, target, scan_type, ports, services, vulnerabilities, risk_level, raw_output, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result.id, scan_result.timestamp, scan_result.target, 
                scan_result.scan_type, json.dumps(scan_result.ports),
                json.dumps(scan_result.services), json.dumps(scan_result.vulnerabilities),
                scan_result.risk_level, json.dumps(asdict(scan_result)), 0.0
            ))
            self.conn.commit()
            
            # Save to file
            scan_file = os.path.join(SCANS_DIR, f"scan_{scan_result.id}.json")
            with open(scan_file, 'w') as f:
                json.dump(asdict(scan_result), f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_traceroute(self, target: str, command: str, output: str, 
                      execution_time: float, hops: int, success: bool = True):
        """Log traceroute results"""
        try:
            result_id = str(uuid.uuid4())
            self.cursor.execute('''
                INSERT INTO traceroute_results 
                (id, target, command, output, execution_time, hops, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (result_id, target, command, output, execution_time, hops, success))
            self.conn.commit()
            return result_id
        except Exception as e:
            logger.error(f"Failed to log traceroute: {e}")
            return None
    
    def log_system_metrics(self):
        """Log system metrics"""
        try:
            metrics_id = str(uuid.uuid4())
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net_io = psutil.net_io_counters()
            connections = len(psutil.net_connections())
            processes = len(psutil.pids())
            
            self.cursor.execute('''
                INSERT INTO system_metrics 
                (id, cpu_percent, memory_percent, disk_percent, network_sent, 
                 network_recv, connections_count, processes_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics_id, cpu_percent, memory.percent, disk.percent,
                net_io.bytes_sent, net_io.bytes_recv, connections, processes
            ))
            self.conn.commit()
            return metrics_id
        except Exception as e:
            logger.error(f"Failed to log system metrics: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 10, severity: str = None) -> List[Dict]:
        """Get recent threats"""
        try:
            if severity:
                self.cursor.execute('''
                    SELECT * FROM threats 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (severity, limit))
            else:
                self.cursor.execute('''
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20, source: str = None) -> List[Dict]:
        """Get command history"""
        try:
            if source:
                self.cursor.execute('''
                    SELECT command, source, timestamp, success, execution_time, user 
                    FROM commands 
                    WHERE source = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (source, limit))
            else:
                self.cursor.execute('''
                    SELECT command, source, timestamp, success, execution_time, user 
                    FROM commands 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
                
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def generate_report(self, report_type: str = 'daily', format: str = 'json') -> str:
        """Generate comprehensive report"""
        try:
            report_id = str(uuid.uuid4())
            report_time = datetime.datetime.now()
            
            if report_type == 'daily':
                hours = 24
            elif report_type == 'weekly':
                hours = 168
            elif report_type == 'monthly':
                hours = 720
            else:
                hours = 24
            
            stats = self.get_system_stats(hours)
            recent_threats = self.get_recent_threats(50)
            
            report = {
                'report_id': report_id,
                'generated_at': report_time.isoformat(),
                'report_type': report_type,
                'time_period_hours': hours,
                'summary': stats,
                'recent_threats': recent_threats[:10],
                'system_info': {
                    'hostname': socket.gethostname(),
                    'os': platform.system(),
                    'os_version': platform.release(),
                    'python_version': platform.python_version(),
                    'cpu_count': psutil.cpu_count(),
                    'total_memory_gb': psutil.virtual_memory().total / (1024**3),
                    'disk_total_gb': psutil.disk_usage('/').total / (1024**3)
                }
            }
            
            # Save report
            if format == 'json':
                filename = f"report_{report_type}_{report_id}.json"
                filepath = os.path.join(REPORT_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return ""
    
    def get_system_stats(self, hours: int = 24) -> Dict:
        """Get system statistics"""
        try:
            time_threshold = datetime.datetime.now() - datetime.timedelta(hours=hours)
            
            # Get threat counts
            self.cursor.execute('''
                SELECT 
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
                FROM threats 
                WHERE timestamp > ?
            ''', (time_threshold.isoformat(),))
            
            threats = self.cursor.fetchone()
            
            # Get command counts
            self.cursor.execute('''
                SELECT 
                    COUNT(*) as total_commands,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN source = 'telegram' THEN 1 ELSE 0 END) as telegram,
                    SUM(CASE WHEN source = 'local' THEN 1 ELSE 0 END) as local
                FROM commands 
                WHERE timestamp > ?
            ''', (time_threshold.isoformat(),))
            
            commands = self.cursor.fetchone()
            
            return {
                'threats': threats,
                'commands': commands,
                'time_period_hours': hours
            }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except:
            pass

# ============================
# NETWORK SCANNER
# ============================
class NetworkScanner:
    """Network scanning capabilities with Nmap integration"""
    
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.traceroute_tool = TracerouteTool(db_manager)
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute using the dedicated tool"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

# ============================
# COMMAND EXECUTOR
# ============================
class CommandExecutor:
    """Enhanced command executor with comprehensive features"""
    
    def __init__(self, db_manager: DatabaseManager, scanner: NetworkScanner):
        self.db = db_manager
        self.scanner = scanner
        self.traceroute_tool = scanner.traceroute_tool
    
    @staticmethod
    def execute_command(cmd: str, timeout: int = 60) -> Tuple[bool, str, float]:
        """Execute shell command with timing"""
        start_time = time.time()
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=timeout)
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                return True, result.stdout, execution_time
            else:
                error_output = result.stderr if result.stderr else result.stdout
                return False, error_output, execution_time
                
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return False, "Command timed out", execution_time
        except Exception as e:
            execution_time = time.time() - start_time
            return False, str(e), execution_time
    
    def ping(self, args: List[str]) -> str:
        """Execute ping command with various options"""
        if not args:
            return "Usage: ping <ip> [options]\nExamples:\n  ping 8.8.8.8 -c 4\n  ping google.com -i 0.2\n  ping 1.1.1.1 -s 1024 -t 64"
        
        ip = args[0]
        options = args[1:] if len(args) > 1 else []
        
        if os.name == 'nt':  # Windows
            cmd = ['ping'] + options + [ip]
        else:  # Linux/Mac
            cmd = ['ping'] + options + [ip]
        
        success, output, exec_time = self.execute_command(' '.join(cmd))
        self.db.log_command(f"ping {' '.join(args)}", 'local', success, output[:1000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def traceroute(self, args: List[str]) -> str:
        """Execute traceroute"""
        if not args:
            return "Usage: traceroute <target>"
        
        return self.traceroute_tool.interactive_traceroute(args[0])
    
    def advanced_traceroute(self, args: List[str]) -> str:
        """Execute enhanced traceroute"""
        if not args:
            return "Usage: advanced_traceroute <target>"
        
        return self.traceroute_tool.interactive_traceroute(args[0], advanced=True)
    
    def nmap(self, args: List[str]) -> str:
        """Execute nmap command with various options"""
        if not args:
            return "Usage: nmap <ip> [options]\nExamples:\n  nmap 192.168.1.1\n  nmap 192.168.1.1 -sS -p 80,443\n  nmap 192.168.1.1 -A -T4"
        
        cmd = f"nmap {' '.join(args)}"
        self.db.log_command(cmd, 'local', True, "Starting nmap scan...", 0)
        
        print(f"Starting nmap scan: {cmd}")
        success, output, exec_time = self.execute_command(cmd, timeout=300)
        
        # Log results
        self.db.log_command(cmd, 'local', success, output[:5000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def curl(self, args: List[str]) -> str:
        """Execute curl command with various options"""
        if not args:
            return "Usage: curl <url> [options]\nExamples:\n  curl https://api.github.com\n  curl -I https://example.com\n  curl -X POST -d 'data=test' https://example.com"
        
        cmd = f"curl {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:2000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def ssh(self, args: List[str]) -> str:
        """Execute ssh command"""
        if not args:
            return "Usage: ssh <host> [options]"
        
        cmd = f"ssh {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd, timeout=30)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        
        return output if success else f"Error: {output}"
    
    def get_ip_location(self, args: List[str]) -> str:
        """Get IP location"""
        if not args:
            return "Usage: location <ip>"
        
        ip = args[0]
        return self.scanner.get_ip_location(ip)
    
    def whois(self, args): 
        if not args:
            return "Usage: whois <domain>"
        domain = args[0]
        cmd = f"whois {domain}"
        success, output, exec_time = self.execute_command(cmd, timeout=30)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def dns_lookup(self, args): 
        if not args:
            return "Usage: dns <domain>"
        domain = args[0]
        try:
            ip = socket.gethostbyname(domain)
            result = f"DNS Lookup: {domain} → {ip}"
            self.db.log_command(f"dns {domain}", 'local', True, result, 0)
            return result
        except Exception as e:
            return f"Error: {str(e)}"
    
    def scan(self, args): 
        if not args:
            return "Usage: scan <ip>"
        return self.nmap([args[0], "-T4", "-F"])
    
    def deep_scan(self, args): 
        if not args:
            return "Usage: deep <ip>"
        return self.nmap([args[0], "-A", "-T4", "-p-"])
    
    def port_scan(self, args): 
        if not args:
            return "Usage: portscan <ip> [ports]"
        ports = args[1] if len(args) > 1 else "1-1000"
        return self.nmap([args[0], "-sS", f"-p{ports}"])
    
    def geolocate(self, args): 
        return self.get_ip_location(args)
    
    def analyze_ip(self, args: List[str]) -> str:
        """Analyze IP comprehensively"""
        if not args:
            return "Usage: analyze <ip>"
        
        ip = args[0]
        result = f"🔍 COMPREHENSIVE ANALYSIS: {ip}\n\n"
        
        # Get location
        location = self.get_ip_location([ip])
        try:
            loc_data = json.loads(location)
            result += f"📍 GEO LOCATION\n"
            result += f"Country: {loc_data.get('country', 'N/A')}\n"
            result += f"Region: {loc_data.get('region', 'N/A')}\n"
            result += f"City: {loc_data.get('city', 'N/A')}\n"
            result += f"ISP: {loc_data.get('isp', 'N/A')}\n"
            result += f"Organization: {loc_data.get('org', 'N/A')}\n\n"
        except:
            result += f"📍 Location: {location}\n\n"
        
        # Check threats
        threats = self.db.get_recent_threats(10)
        ip_threats = [t for t in threats if t.get('source_ip') == ip or t.get('target_ip') == ip]
        
        if ip_threats:
            result += f"🚨 THREATS DETECTED: {len(ip_threats)}\n"
            for threat in ip_threats[:5]:
                result += f"• {threat.get('threat_type', 'Unknown')} ({threat.get('severity', 'Unknown')})\n"
                result += f"  Time: {threat.get('timestamp', 'Unknown')}\n"
        else:
            result += "✅ No recent threats detected\n"
        
        self.db.log_command(f"analyze {ip}", 'local', True, result, 0)
        
        return result
    
    def system_info(self, args: List[str]) -> str:
        """Get detailed system information"""
        info = []
        info.append(f"🏢 SYSTEM INFORMATION")
        info.append(f"System: {platform.system()} {platform.release()}")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"Processor: {platform.processor()}")
        info.append(f"Python: {platform.python_version()}")
        info.append("")
        
        # CPU Info
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        info.append(f"💻 CPU INFORMATION")
        info.append(f"Cores: {psutil.cpu_count()} (Physical: {psutil.cpu_count(logical=False)})")
        info.append(f"Usage: {psutil.cpu_percent()}%")
        info.append(f"Per Core: {', '.join([f'{p}%' for p in cpu_percent])}")
        info.append("")
        
        # Memory Info
        mem = psutil.virtual_memory()
        info.append(f"🧠 MEMORY INFORMATION")
        info.append(f"Total: {mem.total / (1024**3):.2f} GB")
        info.append(f"Available: {mem.available / (1024**3):.2f} GB")
        info.append(f"Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)")
        info.append(f"Free: {mem.free / (1024**3):.2f} GB")
        info.append("")
        
        # Disk Info
        disk = psutil.disk_usage('/')
        info.append(f"💾 DISK INFORMATION")
        info.append(f"Total: {disk.total / (1024**3):.2f} GB")
        info.append(f"Used: {disk.used / (1024**3):.2f} GB ({disk.percent}%)")
        info.append(f"Free: {disk.free / (1024**3):.2f} GB")
        info.append("")
        
        # Network Info
        info.append(f"🌐 NETWORK INFORMATION")
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        info.append(f"Hostname: {hostname}")
        info.append(f"Local IP: {local_ip}")
        
        net_info = psutil.net_if_addrs()
        for interface, addresses in list(net_info.items())[:3]:
            info.append(f"\n{interface}:")
            for addr in addresses[:2]:
                info.append(f"  {addr.family.name}: {addr.address}")
        
        self.db.log_command("system_info", 'local', True, '\n'.join(info), 0)
        
        return '\n'.join(info)
    
    def network_info(self, args: List[str]) -> str:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        result = f"🌐 NETWORK INFORMATION\n\n"
        result += f"Hostname: {hostname}\n"
        result += f"Local IP: {local_ip}\n"
        result += f"Active Connections: {len(psutil.net_connections())}\n"
        
        self.db.log_command("network_info", 'local', True, result, 0)
        return result
    
    def system_metrics(self, args: List[str]) -> str:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        result = f"📊 SYSTEM METRICS\n\n"
        result += f"CPU Usage: {cpu}%\n"
        result += f"Memory Usage: {mem.percent}% ({mem.used / (1024**3):.1f} GB used)\n"
        result += f"Disk Usage: {disk.percent}% ({disk.used / (1024**3):.1f} GB used)\n"
        
        self.db.log_command("metrics", 'local', True, result, 0)
        return result
    
    def iperf(self, args: List[str]) -> str:
        if not args:
            return "Usage: iperf <server> [options]"
        cmd = f"iperf {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def hping3(self, args: List[str]) -> str:
        if not args:
            return "Usage: hping3 <ip> [options]"
        cmd = f"hping3 {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def wget(self, args: List[str]) -> str:
        if not args:
            return "Usage: wget <url> [options]"
        cmd = f"wget {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def nc(self, args: List[str]) -> str:
        if not args:
            return "Usage: nc <options>"
        cmd = f"nc {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def dig(self, args: List[str]) -> str:
        if not args:
            return "Usage: dig <domain> [options]"
        cmd = f"dig {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def nslookup(self, args: List[str]) -> str:
        if not args:
            return "Usage: nslookup <domain>"
        cmd = f"nslookup {' '.join(args)}"
        success, output, exec_time = self.execute_command(cmd)
        self.db.log_command(cmd, 'local', success, output[:1000], exec_time)
        return output if success else f"Error: {output}"
    
    def execute(self, command: str) -> str:
        """Execute any command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Map commands to methods
        command_map = {
            'ping': self.ping,
            'traceroute': self.traceroute,
            'tracert': self.traceroute,
            'advanced_traceroute': self.advanced_traceroute,
            'nmap': self.nmap,
            'curl': self.curl,
            'ssh': self.ssh,
            'whois': self.whois,
            'dns': self.dns_lookup,
            'location': self.get_ip_location,
            'analyze': self.analyze_ip,
            'scan': self.scan,
            'deep': self.deep_scan,
            'portscan': self.port_scan,
            'geo': self.geolocate,
            'system': self.system_info,
            'network': self.network_info,
            'metrics': self.system_metrics,
            'iperf': self.iperf,
            'hping3': self.hping3,
            'wget': self.wget,
            'nc': self.nc,
            'dig': self.dig,
            'nslookup': self.nslookup,
        }
        
        if cmd in command_map:
            try:
                start_time = time.time()
                result = command_map[cmd](args)
                execution_time = time.time() - start_time
                return result
            except Exception as e:
                error_msg = f"Error executing {cmd}: {str(e)}"
                self.db.log_command(command, 'local', False, error_msg, 0)
                return error_msg
        else:
            # Try to execute as shell command
            success, output, exec_time = self.execute_command(command)
            self.db.log_command(command, 'local', success, output[:1000], exec_time)
            
            if success:
                return output
            else:
                return f"Unknown command: {cmd}\nType 'help' for available commands."

# ============================
# TELEGRAM BOT
# ============================
class TelegramBot:
    """Enhanced Telegram bot with 300+ commands"""
    
    def __init__(self, db_manager: DatabaseManager, executor: CommandExecutor, scanner: NetworkScanner):
        self.db = db_manager
        self.executor = executor
        self.scanner = scanner
        self.token = None
        self.chat_id = None
        self.last_update_id = 0
        self.monitored_ips = set()
        self.load_config()
        self.command_handlers = self.setup_command_handlers()
    
    def load_config(self):
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.chat_id = config.get('chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
    
    def save_config(self):
        """Save Telegram configuration"""
        try:
            config = {
                'token': self.token,
                'chat_id': self.chat_id,
                'monitored_ips': list(self.monitored_ips),
                'enabled': bool(self.token and self.chat_id)
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    def setup_command_handlers(self) -> Dict:
        """Setup comprehensive command handlers (300+ commands)"""
        handlers = {
            # Basic commands
            '/start': self.handle_start,
            '/help': self.handle_help,
            
            # Ping commands (50+ variations)
            '/ping': self.handle_ping,
            '/ping_c4': lambda args: self.handle_ping(['-c', '4'] + args),
            '/ping_c10': lambda args: self.handle_ping(['-c', '10'] + args),
            '/ping_i0.2': lambda args: self.handle_ping(['-i', '0.2'] + args),
            '/ping_i1': lambda args: self.handle_ping(['-i', '1'] + args),
            '/ping_w5': lambda args: self.handle_ping(['-w', '5'] + args),
            '/ping_w10': lambda args: self.handle_ping(['-w', '10'] + args),
            '/ping_W1': lambda args: self.handle_ping(['-W', '1'] + args),
            '/ping_W3': lambda args: self.handle_ping(['-W', '3'] + args),
            '/ping_t32': lambda args: self.handle_ping(['-t', '32'] + args),
            '/ping_t64': lambda args: self.handle_ping(['-t', '64'] + args),
            '/ping_s56': lambda args: self.handle_ping(['-s', '56'] + args),
            '/ping_s512': lambda args: self.handle_ping(['-s', '512'] + args),
            '/ping_s1024': lambda args: self.handle_ping(['-s', '1024'] + args),
            '/ping_n': lambda args: self.handle_ping(['-n'] + args),
            '/ping_q': lambda args: self.handle_ping(['-q'] + args),
            '/ping_v': lambda args: self.handle_ping(['-v'] + args),
            '/ping_D': lambda args: self.handle_ping(['-D'] + args),
            '/ping_O': lambda args: self.handle_ping(['-O'] + args),
            '/ping_U': lambda args: self.handle_ping(['-U'] + args),
            '/ping_4': lambda args: self.handle_ping(['-4'] + args),
            '/ping_6': lambda args: self.handle_ping(['-6'] + args),
            '/ping_b': lambda args: self.handle_ping(['-b'] + args),
            '/ping_B': lambda args: self.handle_ping(['-B'] + args),
            '/ping_d': lambda args: self.handle_ping(['-d'] + args),
            '/ping_f': lambda args: self.handle_ping(['-f'] + args),
            '/ping_l5': lambda args: self.handle_ping(['-l', '5'] + args),
            '/ping_l10': lambda args: self.handle_ping(['-l', '10'] + args),
            '/ping_Ieth0': lambda args: self.handle_ping(['-I', 'eth0'] + args),
            '/ping_Iwlan0': lambda args: self.handle_ping(['-I', 'wlan0'] + args),
            '/ping_Mdo': lambda args: self.handle_ping(['-M', 'do'] + args),
            '/ping_c4_i0.5': lambda args: self.handle_ping(['-c', '4', '-i', '0.5'] + args),
            '/ping_c5_W2': lambda args: self.handle_ping(['-c', '5', '-W', '2'] + args),
            '/ping_c10_s1024': lambda args: self.handle_ping(['-c', '10', '-s', '1024'] + args),
            '/ping_c3_t64': lambda args: self.handle_ping(['-c', '3', '-t', '64'] + args),
            '/ping_c5_n_q': lambda args: self.handle_ping(['-c', '5', '-n', '-q'] + args),
            '/ping_c5_D': lambda args: self.handle_ping(['-c', '5', '-D'] + args),
            '/ping_c5_Ieth0': lambda args: self.handle_ping(['-c', '5', '-I', 'eth0'] + args),
            '/ping_c5_4': lambda args: self.handle_ping(['-c', '5', '-4'] + args),
            '/ping_c5_6': lambda args: self.handle_ping(['-c', '5', '-6'] + args),
            
            # Nmap commands (100+ variations)
            '/nmap': self.handle_nmap,
            '/nmap_sn': lambda args: self.handle_nmap(['-sn'] + args),
            '/nmap_Pn': lambda args: self.handle_nmap(['-Pn'] + args),
            '/nmap_n': lambda args: self.handle_nmap(['-n'] + args),
            '/nmap_R': lambda args: self.handle_nmap(['-R'] + args),
            '/nmap_v': lambda args: self.handle_nmap(['-v'] + args),
            '/nmap_vv': lambda args: self.handle_nmap(['-vv'] + args),
            '/nmap_d': lambda args: self.handle_nmap(['-d'] + args),
            '/nmap_dd': lambda args: self.handle_nmap(['-dd'] + args),
            '/nmap_p80': lambda args: self.handle_nmap(['-p', '80'] + args),
            '/nmap_p22_80_443': lambda args: self.handle_nmap(['-p', '22,80,443'] + args),
            '/nmap_p1_1000': lambda args: self.handle_nmap(['-p', '1-1000'] + args),
            '/nmap_pall': lambda args: self.handle_nmap(['-p-'] + args),
            '/nmap_top100': lambda args: self.handle_nmap(['--top-ports', '100'] + args),
            '/nmap_top1000': lambda args: self.handle_nmap(['--top-ports', '1000'] + args),
            '/nmap_F': lambda args: self.handle_nmap(['-F'] + args),
            '/nmap_sS': lambda args: self.handle_nmap(['-sS'] + args),
            '/nmap_sT': lambda args: self.handle_nmap(['-sT'] + args),
            '/nmap_sU': lambda args: self.handle_nmap(['-sU'] + args),
            '/nmap_sA': lambda args: self.handle_nmap(['-sA'] + args),
            '/nmap_sW': lambda args: self.handle_nmap(['-sW'] + args),
            '/nmap_sM': lambda args: self.handle_nmap(['-sM'] + args),
            '/nmap_sN': lambda args: self.handle_nmap(['-sN'] + args),
            '/nmap_sF': lambda args: self.handle_nmap(['-sF'] + args),
            '/nmap_sX': lambda args: self.handle_nmap(['-sX'] + args),
            '/nmap_sO': lambda args: self.handle_nmap(['-sO'] + args),
            '/nmap_sL': lambda args: self.handle_nmap(['-sL'] + args),
            '/nmap_O': lambda args: self.handle_nmap(['-O'] + args),
            '/nmap_osscan_guess': lambda args: self.handle_nmap(['--osscan-guess'] + args),
            '/nmap_fuzzy': lambda args: self.handle_nmap(['--fuzzy'] + args),
            '/nmap_A': lambda args: self.handle_nmap(['-A'] + args),
            '/nmap_sV': lambda args: self.handle_nmap(['-sV'] + args),
            '/nmap_version_all': lambda args: self.handle_nmap(['--version-all'] + args),
            '/nmap_version_light': lambda args: self.handle_nmap(['--version-light'] + args),
            '/nmap_version_trace': lambda args: self.handle_nmap(['--version-trace'] + args),
            '/nmap_T0': lambda args: self.handle_nmap(['-T0'] + args),
            '/nmap_T1': lambda args: self.handle_nmap(['-T1'] + args),
            '/nmap_T2': lambda args: self.handle_nmap(['-T2'] + args),
            '/nmap_T3': lambda args: self.handle_nmap(['-T3'] + args),
            '/nmap_T4': lambda args: self.handle_nmap(['-T4'] + args),
            '/nmap_T5': lambda args: self.handle_nmap(['-T5'] + args),
            '/nmap_min_rate1000': lambda args: self.handle_nmap(['--min-rate', '1000'] + args),
            '/nmap_max_rate5000': lambda args: self.handle_nmap(['--max-rate', '5000'] + args),
            '/nmap_max_retries3': lambda args: self.handle_nmap(['--max-retries', '3'] + args),
            '/nmap_host_timeout30s': lambda args: self.handle_nmap(['--host-timeout', '30s'] + args),
            '/nmap_scan_delay1s': lambda args: self.handle_nmap(['--scan-delay', '1s'] + args),
            '/nmap_f': lambda args: self.handle_nmap(['-f'] + args),
            '/nmap_ttl64': lambda args: self.handle_nmap(['--ttl', '64'] + args),
            '/nmap_badsum': lambda args: self.handle_nmap(['--badsum'] + args),
            '/nmap_script_default': lambda args: self.handle_nmap(['--script', 'default'] + args),
            '/nmap_script_vuln': lambda args: self.handle_nmap(['--script', 'vuln'] + args),
            '/nmap_script_auth': lambda args: self.handle_nmap(['--script', 'auth'] + args),
            '/nmap_script_discovery': lambda args: self.handle_nmap(['--script', 'discovery'] + args),
            '/nmap_script_safe': lambda args: self.handle_nmap(['--script', 'safe'] + args),
            '/nmap_script_intrusive': lambda args: self.handle_nmap(['--script', 'intrusive'] + args),
            '/nmap_script_malware': lambda args: self.handle_nmap(['--script', 'malware'] + args),
            '/nmap_script_http_enum': lambda args: self.handle_nmap(['--script', 'http-enum'] + args),
            '/nmap_script_smb_os_discovery': lambda args: self.handle_nmap(['--script', 'smb-os-discovery'] + args),
            '/nmap_script_ssl_enum_ciphers': lambda args: self.handle_nmap(['--script', 'ssl-enum-ciphers'] + args),
            '/nmap_script_dns_brute': lambda args: self.handle_nmap(['--script', 'dns-brute'] + args),
            '/nmap_script_ftp_anon': lambda args: self.handle_nmap(['--script', 'ftp-anon'] + args),
            '/nmap_script_ssh_hostkey': lambda args: self.handle_nmap(['--script', 'ssh-hostkey'] + args),
            '/nmap_oN': lambda args: self.handle_nmap(['-oN', 'scan.txt'] + args),
            '/nmap_oX': lambda args: self.handle_nmap(['-oX', 'scan.xml'] + args),
            '/nmap_oG': lambda args: self.handle_nmap(['-oG', 'scan.gnmap'] + args),
            '/nmap_oA': lambda args: self.handle_nmap(['-oA', 'scan_all'] + args),
            '/nmap_open': lambda args: self.handle_nmap(['--open'] + args),
            '/nmap_reason': lambda args: self.handle_nmap(['--reason'] + args),
            '/nmap_traceroute': lambda args: self.handle_nmap(['--traceroute'] + args),
            '/nmap_packet_trace': lambda args: self.handle_nmap(['--packet-trace'] + args),
            '/nmap_iflist': lambda args: self.handle_nmap(['--iflist'] + args),
            
            # Curl commands (100+ variations)
            '/curl': self.handle_curl,
            '/curl_I': lambda args: self.handle_curl(['-I'] + args),
            '/curl_i': lambda args: self.handle_curl(['-i'] + args),
            '/curl_v': lambda args: self.handle_curl(['-v'] + args),
            '/curl_s': lambda args: self.handle_curl(['-s'] + args),
            '/curl_S': lambda args: self.handle_curl(['-S'] + args),
            '/curl_L': lambda args: self.handle_curl(['-L'] + args),
            '/curl_k': lambda args: self.handle_curl(['-k'] + args),
            '/curl_XGET': lambda args: self.handle_curl(['-X', 'GET'] + args),
            '/curl_XPOST': lambda args: self.handle_curl(['-X', 'POST'] + args),
            '/curl_XPUT': lambda args: self.handle_curl(['-X', 'PUT'] + args),
            '/curl_XDELETE': lambda args: self.handle_curl(['-X', 'DELETE'] + args),
            '/curl_XOPTIONS': lambda args: self.handle_curl(['-X', 'OPTIONS'] + args),
            '/curl_XHEAD': lambda args: self.handle_curl(['-X', 'HEAD'] + args),
            '/curl_H_accept_json': lambda args: self.handle_curl(['-H', 'Accept: application/json'] + args),
            '/curl_H_content_type_json': lambda args: self.handle_curl(['-H', 'Content-Type: application/json'] + args),
            '/curl_H_user_agent_curl': lambda args: self.handle_curl(['-H', 'User-Agent: curl'] + args),
            '/curl_d_key_value': lambda args: self.handle_curl(['-d', 'key=value'] + args),
            '/curl_d_json': lambda args: self.handle_curl(["-d", '{"key":"value"}'] + args),
            '/curl_F_file': lambda args: self.handle_curl(['-F', 'file=@file.txt'] + args),
            '/curl_json': lambda args: self.handle_curl(['--json', '{"key":"value"}'] + args),
            '/curl_u_user_pass': lambda args: self.handle_curl(['-u', 'user:password'] + args),
            '/curl_u_user': lambda args: self.handle_curl(['-u', 'user'] + args),
            '/curl_anyauth': lambda args: self.handle_curl(['--anyauth'] + args),
            '/curl_basic': lambda args: self.handle_curl(['--basic'] + args),
            '/curl_digest': lambda args: self.handle_curl(['--digest'] + args),
            '/curl_ntlm': lambda args: self.handle_curl(['--ntlm'] + args),
            '/curl_negotiate': lambda args: self.handle_curl(['--negotiate'] + args),
            '/curl_b': lambda args: self.handle_curl(['-b', 'cookies.txt'] + args),
            '/curl_c': lambda args: self.handle_curl(['-c', 'cookies.txt'] + args),
            '/curl_o': lambda args: self.handle_curl(['-o', 'output.txt'] + args),
            '/curl_O': lambda args: self.handle_curl(['-O'] + args),
            '/curl_limit_rate_100k': lambda args: self.handle_curl(['--limit-rate', '100k'] + args),
            '/curl_max_time10': lambda args: self.handle_curl(['--max-time', '10'] + args),
            '/curl_connect_timeout5': lambda args: self.handle_curl(['--connect-timeout', '5'] + args),
            '/curl_retry5': lambda args: self.handle_curl(['--retry', '5'] + args),
            '/curl_retry_delay2': lambda args: self.handle_curl(['--retry-delay', '2'] + args),
            '/curl_compressed': lambda args: self.handle_curl(['--compressed'] + args),
            '/curl_http1.1': lambda args: self.handle_curl(['--http1.1'] + args),
            '/curl_http2': lambda args: self.handle_curl(['--http2'] + args),
            '/curl_tlsv1.2': lambda args: self.handle_curl(['--tlsv1.2'] + args),
            '/curl_tlsv1.3': lambda args: self.handle_curl(['--tlsv1.3'] + args),
            '/curl_proxy': lambda args: self.handle_curl(['--proxy', 'http://proxy:8080'] + args),
            '/curl_proxy_user': lambda args: self.handle_curl(['--proxy-user', 'user:pass'] + args),
            '/curl_socks5': lambda args: self.handle_curl(['--socks5', 'proxy:1080'] + args),
            '/curl_interface': lambda args: self.handle_curl(['--interface', 'eth0'] + args),
            '/curl_fail': lambda args: self.handle_curl(['--fail'] + args),
            '/curl_upload_file': lambda args: self.handle_curl(['--upload-file', 'file.txt'] + args),
            '/curl_T': lambda args: self.handle_curl(['-T', 'file.txt'] + args),
            
            # SSH commands (50+ variations)
            '/ssh': self.handle_ssh,
            '/ssh_p22': lambda args: self.handle_ssh(['-p', '22'] + args),
            '/ssh_p2222': lambda args: self.handle_ssh(['-p', '2222'] + args),
            '/ssh_l': lambda args: self.handle_ssh(['-l'] + args),
            '/ssh_v': lambda args: self.handle_ssh(['-v'] + args),
            '/ssh_vv': lambda args: self.handle_curl(['-vv'] + args),
            '/ssh_vvv': lambda args: self.handle_ssh(['-vvv'] + args),
            '/ssh_q': lambda args: self.handle_ssh(['-q'] + args),
            '/ssh_C': lambda args: self.handle_ssh(['-C'] + args),
            '/ssh_N': lambda args: self.handle_ssh(['-N'] + args),
            '/ssh_T': lambda args: self.handle_ssh(['-T'] + args),
            '/ssh_X': lambda args: self.handle_ssh(['-X'] + args),
            '/ssh_Y': lambda args: self.handle_ssh(['-Y'] + args),
            '/ssh_4': lambda args: self.handle_ssh(['-4'] + args),
            '/ssh_6': lambda args: self.handle_ssh(['-6'] + args),
            '/ssh_A': lambda args: self.handle_ssh(['-A'] + args),
            '/ssh_a': lambda args: self.handle_ssh(['-a'] + args),
            '/ssh_K': lambda args: self.handle_ssh(['-K'] + args),
            '/ssh_k': lambda args: self.handle_ssh(['-k'] + args),
            '/ssh_i_rsa': lambda args: self.handle_ssh(['-i', '~/.ssh/id_rsa'] + args),
            '/ssh_i_ed25519': lambda args: self.handle_ssh(['-i', '~/.ssh/id_ed25519'] + args),
            '/ssh_o_StrictHostKeyChecking_no': lambda args: self.handle_ssh(['-o', 'StrictHostKeyChecking=no'] + args),
            '/ssh_o_ConnectTimeout10': lambda args: self.handle_ssh(['-o', 'ConnectTimeout=10'] + args),
            '/ssh_o_ServerAliveInterval60': lambda args: self.handle_ssh(['-o', 'ServerAliveInterval=60'] + args),
            '/ssh_o_Compression_yes': lambda args: self.handle_ssh(['-o', 'Compression=yes'] + args),
            '/ssh_L8080': lambda args: self.handle_ssh(['-L', '8080:localhost:80'] + args),
            '/ssh_L3306': lambda args: self.handle_ssh(['-L', '3306:localhost:3306'] + args),
            '/ssh_R9000': lambda args: self.handle_ssh(['-R', '9000:localhost:9000'] + args),
            '/ssh_R2222': lambda args: self.handle_ssh(['-R', '2222:localhost:22'] + args),
            '/ssh_D1080': lambda args: self.handle_ssh(['-D', '1080'] + args),
            '/ssh_f_N_L8080': lambda args: self.handle_ssh(['-f', '-N', '-L', '8080:localhost:80'] + args),
            '/ssh_f_N_D1080': lambda args: self.handle_ssh(['-f', '-N', '-D', '1080'] + args),
            '/ssh_J': lambda args: self.handle_ssh(['-J', 'jump@jumphost'] + args),
            '/ssh_b': lambda args: self.handle_ssh(['-b'] + args),
            '/ssh_E': lambda args: self.handle_ssh(['-E', 'ssh.log'] + args),
            '/ssh_F': lambda args: self.handle_ssh(['-F', 'ssh_config'] + args),
            '/ssh_G': lambda args: self.handle_ssh(['-G'] + args),
            '/ssh_Q_cipher': lambda args: self.handle_ssh(['-Q', 'cipher'] + args),
            '/ssh_Q_mac': lambda args: self.handle_ssh(['-Q', 'mac'] + args),
            '/ssh_Q_key': lambda args: self.handle_ssh(['-Q', 'key'] + args),
            '/ssh_Q_kex': lambda args: self.handle_ssh(['-Q', 'kex'] + args),
            '/ssh_m': lambda args: self.handle_ssh(['-m', 'hmac-sha2-256'] + args),
            '/ssh_c': lambda args: self.handle_ssh(['-c', 'aes256-ctr'] + args),
            '/ssh_w0:0': lambda args: self.handle_ssh(['-w', '0:0'] + args),
            
            # Traceroute commands
            '/traceroute': self.handle_traceroute,
            '/advanced_traceroute': self.handle_advanced_traceroute,
            
            # Network traffic generation
            '/iperf': self.handle_iperf,
            '/iperf_t30': lambda args: self.handle_iperf(['-t', '30'] + args),
            '/iperf_i1': lambda args: self.handle_iperf(['-i', '1'] + args),
            '/iperf_p5201': lambda args: self.handle_iperf(['-p', '5201'] + args),
            '/iperf_u': lambda args: self.handle_iperf(['-u'] + args),
            '/iperf_u_b10M': lambda args: self.handle_iperf(['-u', '-b', '10M'] + args),
            '/iperf_u_b100M': lambda args: self.handle_iperf(['-u', '-b', '100M'] + args),
            '/iperf_R': lambda args: self.handle_iperf(['-R'] + args),
            '/iperf_P5': lambda args: self.handle_iperf(['-P', '5'] + args),
            
            '/hping3': self.handle_hping3,
            '/hping3_S': lambda args: self.handle_hping3(['-S'] + args),
            '/hping3_A': lambda args: self.handle_hping3(['-A'] + args),
            '/hping3_F': lambda args: self.handle_hping3(['-F'] + args),
            '/hping3_P': lambda args: self.handle_hping3(['-P'] + args),
            '/hping3_U': lambda args: self.handle_hping3(['-U'] + args),
            '/hping3_S_p80': lambda args: self.handle_hping3(['-S', '-p', '80'] + args),
            '/hping3_flood': lambda args: self.handle_hping3(['--flood'] + args),
            '/hping3_c1000': lambda args: self.handle_hping3(['-c', '1000'] + args),
            '/hping3_iu1000': lambda args: self.handle_hping3(['-i', 'u1000'] + args),
            '/hping3_d120': lambda args: self.handle_hping3(['-d', '120'] + args),
            
            # Information gathering
            '/scan': self.handle_scan,
            '/deep': self.handle_deep_scan,
            '/portscan': self.handle_portscan,
            '/location': self.handle_location,
            '/analyze': self.handle_analyze,
            '/whois': self.handle_whois,
            '/dns': self.handle_dns,
            '/geo': self.handle_geo,
            
            # System info
            '/system': self.handle_system,
            '/network': self.handle_network,
            '/metrics': self.handle_metrics,
            '/status': self.handle_status,
            
            # Utilities
            '/history': self.handle_history,
            '/report': self.handle_report,
            
            # Original AccurateOS commands
            '/start_monitoring_ip': self.handle_start_monitoring_ip,
            '/stop': self.handle_stop,
            '/add_ip': self.handle_add_ip,
            '/remove_ip': self.handle_remove_ip,
            '/list_ips': self.handle_list_ips,
            '/clear': self.handle_clear,
            '/tracert_ip': self.handle_traceroute,
            '/traceroute_ip': self.handle_traceroute,
            '/scan_ip': self.handle_scan,
            '/location_ip': self.handle_location,
            '/analyze_ip': self.handle_analyze,
            '/curl': self.handle_curl,
            '/whois': self.handle_whois,
            '/dns_lookup': self.handle_dns,
            '/network_info': self.handle_network,
            '/system_info': self.handle_system,
            '/threat_summary': self.handle_threat_summary,
            '/generate_report': self.handle_report,
        }
        return handlers
    
    def send_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram with error handling"""
        if not self.token or not self.chat_id:
            logger.error("Telegram not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4000] for i in range(0, len(message), 4000)]
                for msg in messages:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Telegram send failed: {response.text}")
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    return True
                else:
                    logger.error(f"Telegram send failed: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def get_updates(self) -> List[Dict]:
        """Get updates from Telegram"""
        if not self.token:
            return []
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 30,
                'allowed_updates': ['message']
            }
            
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return data.get('result', [])
        except Exception as e:
            logger.error(f"Telegram update error: {e}")
        
        return []
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Telegram connection"""
        if not self.token:
            return False, "Token not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    return True, f"Connected as @{bot_info.get('username', 'Unknown')}"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    # Command Handlers
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>ACCURATE CYBER DEFENSE CYBER DRILL SIMULATION TOOLv1.0.0</b> 🚀

Your comprehensive security monitoring system is online!

<b>🔍 NETWORK COMMANDS (300+):</b>
• /ping [ip] - Ping with various options
• /ping_c4 [ip] - Ping with 4 packets
• /ping_c10 [ip] - Ping with 10 packets
• /ping_i0.2 [ip] - Ping with 0.2s interval
• /ping_s1024 [ip] - Ping with 1024 byte packets
• /ping_c4_i0.5 [ip] - Combined options

<b>🌐 SCANNING & RECONNAISSANCE:</b>
• /nmap [ip] - Complete nmap scanning
• /nmap_sS [ip] - SYN scan
• /nmap_A [ip] - Aggressive scan
• /nmap_sV [ip] - Version detection
• /nmap_T4 [ip] - Fast timing
• /nmap_script_vuln [ip] - Vulnerability scripts

<b>📡 WEB TOOLS:</b>
• /curl [url] - HTTP requests
• /curl_I [url] - Show headers only
• /curl_v [url] - Verbose output
• /curl_XPOST [url] - POST request
• /curl_H_content_type_json [url] - JSON request

<b>🔐 SSH COMMANDS:</b>
• /ssh [host] - SSH connections
• /ssh_p2222 [host] - SSH on port 2222
• /ssh_L8080 [host] - Local port forwarding
• /ssh_D1080 [host] - SOCKS proxy
• /ssh_v [host] - Verbose SSH

<b>🚀 TRAFFIC GENERATION:</b>
• /iperf [server] - Bandwidth testing
• /hping3 [ip] - Traffic generation
• /hping3_flood [ip] - Flood mode
• /hping3_S [ip] - SYN packets

<b>🛡️ SECURITY ANALYSIS:</b>
• /analyze [ip] - Comprehensive analysis
• /location [ip] - IP geolocation
• /whois [domain] - WHOIS lookup
• /dns [domain] - DNS lookup
• /threat_summary - Show recent threats

<b>📊 SYSTEM INFO:</b>
• /system - Detailed system info
• /network - Network information
• /metrics - Real-time metrics
• /status - System status

<b>📁 UTILITIES:</b>
• /history - Command history
• /report - Generate security report
• /traceroute [ip] - Enhanced traceroute
• /advanced_traceroute [ip] - Advanced traceroute
• /start_monitoring_ip [ip] - Start IP monitoring
• /list_ips - List monitored IPs
• /add_ip [ip] - Add IP to monitoring

❓ Type /help for complete command list
💡 All 300+ commands are available!
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        return """
<b>🔒 Complete Command Reference (300+ Commands)</b>

<b>🏓 PING VARIATIONS (50+):</b>
<code>/ping 8.8.8.8</code>
<code>/ping_c4 8.8.8.8</code>
<code>/ping_c10 8.8.8.8</code>
<code>/ping_i0.2 8.8.8.8</code>
<code>/ping_s1024 8.8.8.8</code>
<code>/ping_t64 8.8.8.8</code>
<code>/ping_D 8.8.8.8</code>
<code>/ping_4 8.8.8.8</code>
<code>/ping_6 8.8.8.8</code>
<code>/ping_c4_i0.5 8.8.8.8</code>

<b>🔍 NMAP SCANS (100+):</b>
<code>/nmap 192.168.1.1</code>
<code>/nmap_sS 192.168.1.1</code>
<code>/nmap_sT 192.168.1.1</code>
<code>/nmap_sU 192.168.1.1</code>
<code>/nmap_A 192.168.1.1</code>
<code>/nmap_sV 192.168.1.1</code>
<code>/nmap_T4 192.168.1.1</code>
<code>/nmap_p1_1000 192.168.1.1</code>
<code>/nmap_script_vuln 192.168.1.1</code>
<code>/nmap_script_http_enum 192.168.1.1</code>

<b>🌐 CURL REQUESTS (50+):</b>
<code>/curl https://api.github.com</code>
<code>/curl_I https://example.com</code>
<code>/curl_v https://example.com</code>
<code>/curl_XPOST https://api.example.com</code>
<code>/curl_H_content_type_json https://api.example.com</code>
<code>/curl_d_json https://api.example.com</code>
<code>/curl_u_user_pass https://api.example.com</code>
<code>/curl_proxy http://example.com</code>
<code>/curl_limit_rate_100k https://example.com</code>

<b>🔐 SSH CONNECTIONS (50+):</b>
<code>/ssh user@server</code>
<code>/ssh_p2222 user@server</code>
<code>/ssh_v user@server</code>
<code>/ssh_i_rsa user@server</code>
- Port Forwarding:
<code>/ssh_L8080 user@server</code>
<code>/ssh_R9000 user@server</code>
<code>/ssh_D1080 user@server</code>
<code>/ssh_f_N_L8080 user@server</code>

<b>🚀 TRAFFIC GENERATION:</b>
<code>/iperf server-ip</code>
<code>/iperf_t30 server-ip</code>
<code>/iperf_u_b100M server-ip</code>
<code>/hping3 192.168.1.1</code>
<code>/hping3_S 192.168.1.1</code>
<code>/hping3_flood 192.168.1.1</code>

<b>🛡️ SECURITY TOOLS:</b>
<code>/traceroute example.com</code>
<code>/advanced_traceroute 1.1.1.1</code>
<code>/analyze 192.168.1.1</code>
<code>/location 1.1.1.1</code>
<code>/whois example.com</code>
<code>/dns example.com</code>
<code>/scan 192.168.1.1</code>
<code>/deep 192.168.1.1</code>
<code>/threat_summary</code>
<code>/generate_report</code>

<b>📊 SYSTEM INFO:</b>
<code>/system</code>
<code>/network</code>
<code>/metrics</code>
<code>/status</code>
<code>/history</code>
<code>/report</code>

<b>🎯 MONITORING:</b>
<code>/start_monitoring_ip 192.168.1.1</code>
<code>/add_ip 10.0.0.1</code>
<code>/remove_ip 10.0.0.1</code>
<code>/list_ips</code>
<code>/stop</code>

All commands execute instantly! 🚀
        """
    
    def handle_ping(self, args: List[str]) -> str:
        """Handle ping command"""
        if not args:
            return "❌ Usage: <code>/ping [IP]</code>\nExample: <code>/ping 8.8.8.8</code>"
        
        result = self.executor.ping(args)
        response = f"🏓 <b>Ping Results</b>\n\n"
        response += f"<pre>{result[-1000:]}</pre>"
        return response
    
    def handle_nmap(self, args: List[str]) -> str:
        """Handle nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap [IP] [options]</code>\nExample: <code>/nmap 192.168.1.1</code>"
        
        cmd = f"nmap {' '.join(args)}"
        self.send_message(f"🔍 <b>Starting Nmap scan...</b>\n\n<code>{cmd}</code>")
        
        result = self.executor.nmap(args)
        
        response = f"🔍 <b>Nmap Results</b>\n\n"
        if len(result) > 3000:
            response += f"<pre>{result[-3000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_curl(self, args: List[str]) -> str:
        """Handle curl command"""
        if not args:
            return "❌ Usage: <code>/curl [URL] [options]</code>\nExample: <code>/curl https://api.github.com</code>"
        
        cmd = f"curl {' '.join(args)}"
        result = self.executor.curl(args)
        
        response = f"📡 <b>CURL Results</b>\n\n"
        response += f"Command: <code>{cmd}</code>\n\n"
        
        if len(result) > 2000:
            response += f"<pre>{result[-2000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_ssh(self, args: List[str]) -> str:
        """Handle ssh command"""
        if not args:
            return "❌ Usage: <code>/ssh [host] [options]</code>\nExample: <code>/ssh user@server</code>"
        
        cmd = f"ssh {' '.join(args)}"
        result = self.executor.ssh(args)
        
        response = f"🔐 <b>SSH Results</b>\n\n"
        response += f"Command: <code>{cmd}</code>\n\n"
        
        if len(result) > 1000:
            response += f"<pre>{result[-1000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_traceroute(self, args: List[str]) -> str:
        """Handle traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute [IP/domain]</code>"
        
        target = args[0]
        self.send_message(f"🛣️ <b>Starting traceroute to {target}...</b>")
        
        result = self.executor.traceroute([target])
        return result
    
    def handle_advanced_traceroute(self, args: List[str]) -> str:
        """Handle advanced traceroute command"""
        if not args:
            return "❌ Usage: <code>/advanced_traceroute [IP/domain]</code>"
        
        target = args[0]
        self.send_message(f"🚀 <b>Starting enhanced traceroute to {target}...</b>")
        
        result = self.executor.advanced_traceroute([target])
        return result
    
    def handle_scan(self, args: List[str]) -> str:
        """Handle scan command"""
        if not args:
            return "❌ Usage: <code>/scan [IP]</code>"
        
        ip = args[0]
        self.send_message(f"🔍 <b>Scanning {ip}...</b>")
        
        result = self.executor.scan([ip])
        
        response = f"🔍 <b>Scan Results: {ip}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_deep_scan(self, args: List[str]) -> str:
        """Handle deep scan command"""
        if not args:
            return "❌ Usage: <code>/deep [IP]</code>"
        
        ip = args[0]
        self.send_message(f"🔍 <b>Deep scanning {ip}...</b>")
        
        result = self.executor.deep_scan([ip])
        
        response = f"🔍 <b>Deep Scan Results: {ip}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_portscan(self, args: List[str]) -> str:
        """Handle portscan command"""
        if not args:
            return "❌ Usage: <code>/portscan [IP] [ports]</code>"
        
        ip = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        self.send_message(f"🔍 <b>Port scanning {ip}:{ports}...</b>")
        
        result = self.executor.port_scan([ip, ports])
        
        response = f"🔍 <b>Port Scan Results: {ip}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_location(self, args: List[str]) -> str:
        """Handle location command"""
        if not args:
            return "❌ Usage: <code>/location [IP]</code>"
        
        ip = args[0]
        result = self.executor.get_ip_location([ip])
        
        response = f"🌍 <b>Location: {ip}</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_geo(self, args: List[str]) -> str:
        """Handle geo command"""
        return self.handle_location(args)
    
    def handle_analyze(self, args: List[str]) -> str:
        """Handle analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze [IP]</code>"
        
        ip = args[0]
        result = self.executor.analyze_ip([ip])
        
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_whois(self, args: List[str]) -> str:
        """Handle whois command"""
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        domain = args[0]
        result = self.executor.whois([domain])
        
        response = f"📋 <b>WHOIS: {domain}</b>\n\n"
        response += f"<pre>{result[-2000:]}</pre>"
        
        return response
    
    def handle_dns(self, args: List[str]) -> str:
        """Handle dns command"""
        if not args:
            return "❌ Usage: <code>/dns [domain]</code>"
        
        domain = args[0]
        result = self.executor.dns_lookup([domain])
        
        response = f"🌐 <b>DNS Lookup</b>\n\n"
        response += f"{result}"
        
        return response
    
    def handle_system(self, args: List[str]) -> str:
        """Handle system command"""
        result = self.executor.system_info([])
        
        response = f"💻 <b>System Information</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_network(self, args: List[str]) -> str:
        """Handle network command"""
        result = self.executor.network_info([])
        
        response = f"🌐 <b>Network Information</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_metrics(self, args: List[str]) -> str:
        """Handle metrics command"""
        result = self.executor.system_metrics([])
        
        response = f"📊 <b>System Metrics</b>\n\n"
        response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_status(self, args: List[str]) -> str:
        """Handle status command"""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ Bot: {'Online' if self.token else 'Offline'}\n"
        response += f"💻 CPU: {cpu}%\n"
        response += f"🧠 Memory: {mem.percent}%\n"
        response += f"💾 Disk: {disk.percent}%\n"
        response += f"🌐 Connections: {len(psutil.net_connections())}\n"
        
        return response
    
    def handle_iperf(self, args: List[str]) -> str:
        """Handle iperf command"""
        if not args:
            return "❌ Usage: <code>/iperf [server-ip] [options]</code>"
        
        cmd = f"iperf {' '.join(args)}"
        result = self.executor.iperf(args)
        
        response = f"📊 <b>Iperf Results</b>\n\n"
        response += f"Command: <code>{cmd}</code>\n\n"
        
        if len(result) > 2000:
            response += f"<pre>{result[-2000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_hping3(self, args: List[str]) -> str:
        """Handle hping3 command"""
        if not args:
            return "❌ Usage: <code>/hping3 [ip] [options]</code>"
        
        cmd = f"hping3 {' '.join(args)}"
        result = self.executor.hping3(args)
        
        response = f"🚀 <b>Hping3 Results</b>\n\n"
        response += f"Command: <code>{cmd}</code>\n\n"
        
        if len(result) > 2000:
            response += f"<pre>{result[-2000:]}</pre>"
        else:
            response += f"<pre>{result}</pre>"
        
        return response
    
    def handle_history(self, args: List[str]) -> str:
        """Handle history command"""
        limit = int(args[0]) if args else 10
        history = self.db.get_command_history(limit=limit)
        
        if not history:
            return "📝 No commands recorded"
        
        response = f"📝 <b>Command History (Last {limit})</b>\n\n"
        for entry in history:
            success = "✅" if entry.get('success') else "❌"
            source = entry.get('source', 'unknown')
            cmd = entry.get('command', '')
            timestamp = entry.get('timestamp', '')
            
            response += f"{success} [{source}] <code>{cmd[:50]}</code>\n"
            response += f"   {timestamp}\n\n"
        
        return response
    
    def handle_report(self, args: List[str]) -> str:
        """Handle report command"""
        report_type = args[0] if args else 'daily'
        
        self.send_message(f"📊 <b>Generating {report_type} report...</b>")
        
        filepath = self.db.generate_report(report_type, 'json')
        
        if filepath:
            response = f"📊 <b>Security Report Generated</b>\n\n"
            response += f"Type: {report_type}\n"
            response += f"File: <code>{os.path.basename(filepath)}</code>\n"
            response += f"✅ Report saved successfully"
        else:
            response = "❌ Failed to generate report"
        
        return response
    
    # Original AccurateOS command handlers
    
    def handle_start_monitoring_ip(self, args: List[str]) -> str:
        """Handle start monitoring"""
        if not args:
            return "❌ Usage: <code>/start_monitoring_ip [IP]</code>"
        
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            self.save_config()
            self.db.log_command(f"start_monitoring_ip {ip}", 'telegram', True)
            return f"✅ Started monitoring <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_stop(self, args: List[str]) -> str:
        """Handle stop"""
        if not self.monitored_ips:
            return "⚠️ No IPs are being monitored"
        
        ips = list(self.monitored_ips)
        self.monitored_ips.clear()
        self.save_config()
        return f"🛑 Stopped monitoring: {', '.join(ips)}"
    
    def handle_add_ip(self, args: List[str]) -> str:
        """Handle add IP"""
        if not args:
            return "❌ Usage: <code>/add_ip [IP]</code>"
        
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            self.save_config()
            return f"✅ Added <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_remove_ip(self, args: List[str]) -> str:
        """Handle remove IP"""
        if not args:
            return "❌ Usage: <code>/remove_ip [IP]</code>"
        
        ip = args[0]
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.save_config()
            return f"✅ Removed <code>{ip}</code>"
        return f"❌ IP not in list: <code>{ip}</code>"
    
    def handle_list_ips(self, args: List[str]) -> str:
        """Handle list IPs"""
        if not self.monitored_ips:
            return "📋 No IPs are being monitored"
        
        response = "📋 <b>Monitored IPs</b>\n\n"
        for ip in sorted(self.monitored_ips):
            response += f"• <code>{ip}</code>\n"
        return response
    
    def handle_clear(self, args: List[str]) -> str:
        """Handle clear"""
        try:
            self.cursor.execute('DELETE FROM commands')
            self.conn.commit()
            return "✅ Command history cleared"
        except Exception as e:
            return f"❌ Error clearing history: {e}"
    
    def handle_threat_summary(self, args: List[str]) -> str:
        """Handle threat summary"""
        threats = self.db.get_recent_threats(10)
        
        if not threats:
            return "✅ No recent threats detected"
        
        response = "🚨 <b>Recent Threats</b>\n\n"
        for threat in threats:
            response += f"• <code>{threat.get('source_ip')}</code>\n"
            response += f"  Type: {threat.get('threat_type')} | Severity: {threat.get('severity')}\n"
            response += f"  Time: {threat.get('timestamp')}\n\n"
        
        return response
    
    def process_message(self, message: Dict):
        """Process incoming Telegram message"""
        if 'text' not in message:
            return
        
        text = message['text']
        chat_id = message['chat']['id']
        
        # Set chat ID if not set
        if not self.chat_id:
            self.chat_id = str(chat_id)
            self.save_config()
        
        # Log command
        self.db.log_command(text, 'telegram', True)
        
        parts = text.split()
        if not parts:
            return
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.command_handlers:
            try:
                response = self.command_handlers[command](args)
                self.send_message(response)
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)}"
                self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            self.send_message("❌ Unknown command. Type /help for available commands.")
    
    def process_updates(self):
        """Process all pending updates"""
        updates = self.get_updates()
        
        for update in updates:
            if 'message' in update:
                self.process_message(update['message'])
            
            if 'update_id' in update:
                self.last_update_id = update['update_id']
    
    def run(self):
        """Run Telegram bot in background"""
        logger.info("Starting Telegram bot with 300+ commands...")
        
        while True:
            try:
                self.process_updates()
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                time.sleep(10)

# ============================
# NETWORK MONITOR
# ============================
class NetworkMonitor:
    """Enhanced network monitoring and threat detection with real-time analysis"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.monitoring = False
        self.monitored_ips = set()
        self.db = db_manager
    
    def start_monitoring(self):
        """Start comprehensive network monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already started")
            return
        
        self.monitoring = True
        logger.info("Starting enhanced network monitoring...")
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_port_scan, daemon=True, name="PortScanMonitor"),
            threading.Thread(target=self.monitor_syn_flood, daemon=True, name="SYNFloodMonitor"),
            threading.Thread(target=self.monitor_connections, daemon=True, name="ConnectionMonitor"),
            threading.Thread(target=self.monitor_system_metrics, daemon=True, name="SystemMetricsMonitor"),
        ]
        
        for thread in threads:
            thread.start()
        
        logger.info(f"Started {len(threads)} monitoring threads")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        logger.info("Network monitoring stopped")
    
    def monitor_port_scan(self):
        """Monitor for port scanning activity"""
        logger.info("Port scan monitor started")
        port_attempts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                current_time = time.time()
                
                for conn in connections:
                    if conn.status == 'SYN_SENT' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        if remote_ip not in port_attempts:
                            port_attempts[remote_ip] = {
                                'ports': set(),
                                'first_seen': current_time,
                                'last_seen': current_time,
                                'count': 0
                            }
                        
                        port_attempts[remote_ip]['ports'].add(conn.raddr.port)
                        port_attempts[remote_ip]['last_seen'] = current_time
                        port_attempts[remote_ip]['count'] += 1
                
                # Check for port scanning patterns
                for ip, data in list(port_attempts.items()):
                    time_diff = current_time - data['first_seen']
                    
                    if time_diff > 60:  # 1 minute window
                        port_count = len(data['ports'])
                        attempt_count = data['count']
                        
                        # Detect port scanning
                        if port_count > 10:
                            alert = ThreatAlert(
                                id=str(uuid.uuid4()),
                                timestamp=datetime.datetime.now().isoformat(),
                                threat_type="Port Scanning",
                                source_ip=ip,
                                target_ip="Multiple",
                                severity="high",
                                description=f"Detected port scanning activity: {port_count} ports scanned, {attempt_count} attempts",
                                action_taken="Logged and alerted",
                                resolved=False
                            )
                            
                            self.db.log_threat(alert)
                            logger.warning(f"Port scan detected from {ip}: {port_count} ports")
                            
                            # Remove from monitoring to prevent duplicate alerts
                            del port_attempts[ip]
                
                # Cleanup old entries
                old_ips = [ip for ip, data in port_attempts.items() 
                          if current_time - data['last_seen'] > 300]  # 5 minutes
                for ip in old_ips:
                    del port_attempts[ip]
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Port scan monitor error: {e}")
                time.sleep(10)
    
    def monitor_syn_flood(self):
        """Monitor for SYN flood attacks"""
        logger.info("SYN flood monitor started")
        syn_counts = {}
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                current_time = time.time()
                
                syn_count = 0
                for conn in connections:
                    if conn.status == 'SYN_SENT':
                        syn_count += 1
                
                # Track SYN counts over time
                syn_counts[current_time] = syn_count
                
                # Remove old entries (keep last 60 seconds)
                old_times = [t for t in syn_counts.keys() if current_time - t > 60]
                for t in old_times:
                    del syn_counts[t]
                
                # Calculate average over last minute
                if syn_counts:
                    avg_syn = sum(syn_counts.values()) / len(syn_counts)
                    
                    if avg_syn > 100:
                        alert = ThreatAlert(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.datetime.now().isoformat(),
                            threat_type="SYN Flood",
                            source_ip="Multiple",
                            target_ip=socket.gethostbyname(socket.gethostname()),
                            severity="critical",
                            description=f"Possible SYN flood attack detected: {avg_syn:.1f} average SYN packets/second",
                            action_taken="Logged and alerted",
                            resolved=False
                        )
                        
                        self.db.log_threat(alert)
                        logger.warning(f"SYN flood detected: {avg_syn:.1f} SYN/sec")
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"SYN flood monitor error: {e}")
                time.sleep(5)
    
    def monitor_connections(self):
        """Monitor network connections for anomalies"""
        logger.info("Connection monitor started")
        
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                connection_stats = {
                    'total': len(connections),
                    'established': 0,
                    'syn_sent': 0,
                    'syn_recv': 0,
                    'fin_wait': 0,
                    'time_wait': 0,
                    'close_wait': 0,
                    'listen': 0,
                    'closing': 0,
                    'unknown': 0
                }
                
                for conn in connections:
                    status = conn.status.lower()
                    if status in connection_stats:
                        connection_stats[status] += 1
                    else:
                        connection_stats['unknown'] += 1
                
                # Check for anomalies
                if connection_stats['syn_sent'] > 100 and connection_stats['established'] < 10:
                    # Many SYN packets but few established connections could indicate scanning
                    pass
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
                time.sleep(10)
    
    def monitor_system_metrics(self):
        """Monitor system metrics"""
        logger.info("System metrics monitor started")
        
        while self.monitoring:
            try:
                self.db.log_system_metrics()
                time.sleep(60)  # Log every minute
            except Exception as e:
                logger.error(f"System metrics monitor error: {e}")
                time.sleep(60)

# ============================
# MAIN ACCURATE ONLINE OS
# ============================
class AccurateOnlineOS:
    """Main Accurate Online OS class with comprehensive features"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.scanner = NetworkScanner(self.db)
        self.executor = CommandExecutor(self.db, self.scanner)
        self.telegram = TelegramBot(self.db, self.executor, self.scanner)
        self.monitor = NetworkMonitor(self.db)
        
        self.running = True
        self.telegram_thread = None
        self.monitored_ips = set()
    
    def print_banner(self):
        """Print enhanced tool banner"""
        banner = f"""
{'='*80}
{' '*20}🚀 ACCURATE ONLINE OS ULTIMATE v1.0.0 🚀
{' '*20}  Combined Enhanced Edition with 300+ Commands
{'='*80}

FEATURES:
• 300+ Telegram Commands with Real-time Execution
• Enhanced Traceroute with Geolocation & Visualization
• Complete Network Monitoring & Threat Detection
• Advanced Scanning & Reconnaissance Tools
• Database Logging & Security Reporting
• DDoS Detection & Prevention Systems
• Real-time Alerts & Notifications
• Traffic Generation & Load Testing
• System & Network Information Gathering
• Complete Information Gathering Suite

STATUS:
• Database: {'✅ READY' if os.path.exists(DATABASE_FILE) else '⚠️ SETUP NEEDED'}
• Telegram: {'✅ CONFIGURED' if self.telegram.token else '⚠️ NOT CONFIGURED'}
• Monitoring: {'✅ ACTIVE' if self.monitor.monitoring else '⚠️ INACTIVE'}

COMMANDS:
• Type 'help' for local commands
• Send /start to Telegram bot for 300+ commands
• Type 'exit' to quit
{'='*80}
"""
        print(banner)
    
    def print_help(self):
        """Print comprehensive help message"""
        help_text = f"""
{'='*80}
{' '*25}📖 COMPLETE COMMAND REFERENCE
{'='*80}

🚀 TELEGRAM COMMANDS (300+):
  All commands start with / and are available via Telegram bot
  Examples: /ping 8.8.8.8, /nmap 192.168.1.1, /curl https://api.github.com

💻 LOCAL TERMINAL COMMANDS:

🛡️  MONITORING & SECURITY:
  start_monitoring          - Start threat monitoring
  stop_monitoring           - Stop monitoring
  status                    - Show monitoring status
  threats                   - Show recent threats
  report [type]             - Generate security report

📡 NETWORK DIAGNOSTICS:
  ping <ip> [options]       - Ping with various options
  traceroute <ip>           - Enhanced traceroute
  advanced_traceroute <ip>  - Advanced traceroute with geolocation
  scan <ip>                 - Quick port scan
  deep <ip>                 - Deep port scan
  portscan <ip> <ports>     - Custom port scan

🔍 SCANNING & RECONNAISSANCE:
  nmap <ip> [options]       - Complete nmap scanning
  curl <url> [options]      - HTTP requests
  ssh <host> [options]      - SSH connections
  whois <domain>            - WHOIS lookup
  dns <domain>              - DNS lookup

🌐 INFORMATION GATHERING:
  location <ip>             - IP geolocation
  analyze <ip>              - Comprehensive IP analysis
  geo <ip>                  - Quick geolocation

🚀 NETWORK TRAFFIC GENERATION:
  iperf <server> [options]  - Bandwidth testing
  hping3 <ip> [options]     - Traffic generation

🔧 NETWORK TOOLS:
  wget <url> [options]      - File download
  nc <options>              - Netcat operations
  dig <domain> [options]    - DNS lookup with dig
  nslookup <domain>         - DNS lookup

💻 SYSTEM INFORMATION:
  system                    - Detailed system information
  network                   - Network information
  metrics                   - Real-time system metrics

📊 UTILITIES:
  history [limit]           - Command history
  config                    - Configure Telegram
  clear                     - Clear screen
  help                      - Show this help
  exit                      - Exit tool

{'='*80}
💡 All 300+ commands are available via Telegram!
🚀 Use 'config' command to setup Telegram integration.
{'='*80}
"""
        print(help_text)
    
    def start_telegram_bot(self):
        """Start Telegram bot in background"""
        if self.telegram.token and self.telegram.chat_id:
            self.telegram_thread = threading.Thread(target=self.telegram.run, daemon=True)
            self.telegram_thread.start()
            logger.info("Telegram bot started with 300+ commands")
            
            # Send welcome message
            welcome_msg = """🚀 <b>ACCURATE CYBER DEFENSE CYBER DRILL SIMULATION TOOL v1.0.0 - Connected!</b>

✅ Bot is online and ready
🚀 300+ commands available
🛡️ Security monitoring active
📊 Database logging enabled

Type /help for complete command list
Type /ping 8.8.8.8 to test"""
            self.telegram.send_message(welcome_msg)
        else:
            logger.warning("Telegram not configured. Bot not started.")
    
    def setup_telegram(self):
        """Setup Telegram configuration"""
        print(f"\n{'='*60}")
        print(f"{' '*15}🔧 Telegram Bot Setup")
        print(f"{'='*60}")
        print("\nTo use 300+ Telegram commands:")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your bot token (format: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz)")
        print("3. Start chat with your bot and send /start")
        print("4. Get your chat ID from @userinfobot\n")
        
        setup = input("Configure Telegram now? (y/n): ").lower()
        if setup == 'y':
            token = input("Enter Telegram bot token: ").strip()
            chat_id = input("Enter your chat ID: ").strip()
            
            if token and chat_id:
                self.telegram.token = token
                self.telegram.chat_id = chat_id
                self.telegram.save_config()
                
                print(f"\n✅ Telegram configured successfully!")
                
                # Test connection
                success, message = self.telegram.test_connection()
                if success:
                    print(f"✅ {message}")
                    self.start_telegram_bot()
                else:
                    print(f"❌ {message}")
            else:
                print(f"⚠️ Telegram configuration cancelled")
    
    def check_dependencies(self):
        """Check required dependencies"""
        print(f"\n🔍 Checking dependencies...")
        
        required_packages = ['requests', 'psutil']
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
                print(f"✅ {package}")
            except ImportError:
                print(f"❌ {package} not installed")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n⚠️ Some dependencies are missing.")
            install = input(f"Install missing packages? (y/n): ").lower()
            if install == 'y':
                for package in missing_packages:
                    try:
                        print(f"Installing {package}...")
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print(f"✅ {package} installed")
                    except Exception as e:
                        print(f"❌ Failed to install {package}: {e}")
    
    def run(self):
        """Main run loop"""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup Telegram if not configured
        if not self.telegram.token or not self.telegram.chat_id:
            self.setup_telegram()
        
        # Start Telegram bot
        self.start_telegram_bot()
        
        print(f"\n✅ Accurate Online OS Ultimate v1.0.0 is ready!")
        print(f"💡 Type 'help' for local commands")
        
        if self.telegram.token and self.telegram.chat_id:
            print(f"🤖 Telegram bot: ACTIVE (300+ commands)")
            print(f"📱 Send /start to your bot on Telegram")
        
        print(f"⚠️  Use responsibly and only on networks you own or have permission to test")
        print(f"{'='*80}\n")
        
        # Main command loop
        while self.running:
            try:
                command = input("accurate#> ").strip()
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd == 'exit':
                    print(f"\n👋 Exiting...")
                    self.running = False
                    
                elif cmd == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                    
                elif cmd == 'help':
                    self.print_help()
                    
                elif cmd == 'config':
                    self.setup_telegram()
                    
                elif cmd == 'start_monitoring':
                    self.monitor.start_monitoring()
                    print(f"✅ Monitoring started")
                    
                elif cmd == 'stop_monitoring':
                    self.monitor.stop_monitoring()
                    print(f"⚠️ Monitoring stopped")
                    
                elif cmd == 'status':
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    print(f"\n📊 System Status:")
                    print(f"  Bot: {'Online' if self.telegram.token else 'Offline'}")
                    print(f"  Monitoring: {'Active' if self.monitor.monitoring else 'Inactive'}")
                    print(f"  CPU: {cpu}%")
                    print(f"  Memory: {mem.percent}%")
                    print(f"  Connections: {len(psutil.net_connections())}")
                    
                elif cmd == 'threats':
                    threats = self.db.get_recent_threats(10)
                    if threats:
                        print(f"\n🚨 Recent Threats:")
                        for threat in threats:
                            print(f"  • {threat.get('source_ip')} - {threat.get('threat_type')} ({threat.get('severity')})")
                            print(f"    Time: {threat.get('timestamp')}\n")
                    else:
                        print(f"✅ No recent threats detected")
                        
                elif cmd == 'report':
                    parts = command.split()
                    report_type = parts[1] if len(parts) > 1 else 'daily'
                    filepath = self.db.generate_report(report_type, 'json')
                    if filepath:
                        print(f"✅ Report generated: {filepath}")
                    else:
                        print(f"❌ Failed to generate report")
                        
                elif cmd == 'history':
                    history = self.db.get_command_history(20)
                    if history:
                        print(f"\n📜 Command History:")
                        for entry in history:
                            success = "✅" if entry.get('success') else "❌"
                            source = entry.get('source', 'unknown')
                            cmd_text = entry.get('command', '')
                            timestamp = entry.get('timestamp', '')
                            print(f"  {success} [{source}] {cmd_text[:50]}")
                            print(f"    Time: {timestamp}\n")
                    else:
                        print(f"📜 No commands recorded")
                        
                else:
                    # Execute command via executor
                    result = self.executor.execute(command)
                    if result:
                        print(result)
                        
            except KeyboardInterrupt:
                print(f"\n👋 Exiting...")
                self.running = False
            except Exception as e:
                print(f"❌ Error: {str(e)}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.db.close()
        print(f"✅ Tool shutdown complete.")

# ============================
# MAIN ENTRY POINT
# ============================
def main():
    """Main entry point"""
    try:
        # Create tool instance
        tool = AccurateOnlineOS()
        
        # Run tool
        tool.run()
        
    except KeyboardInterrupt:
        print(f"\n👋 Tool interrupted by user.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"❌ Fatal error occurred. Check {LOG_FILE} for details.")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()