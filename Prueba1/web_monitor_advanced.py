#!/usr/bin/env python3
"""
Script Avanzado de Monitoreo de Seguridad Web
Versión mejorada con análisis más profundo y detección de vulnerabilidades
"""

import subprocess
import re
import json
import time
from datetime import datetime
from collections import defaultdict
import os
import sys
import threading
import queue

# Configuración
TARGET_IP = "10.104.0.19"
TARGET_DOMAINS = ["milnomes.es", "nadieentiendemiletra.milnomes.es"]
# Obtener directorio del script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "web_attacks_log.txt")
UPDATE_INTERVAL = 300  # 5 minutos
INTERFACE = None

# Patrones de ataques expandidos
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
        r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
        r"(?i)(admin'--|admin'#|' or '1'='1|' or 1=1--)",
        r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    ],
    "XSS (Cross-Site Scripting)": [
        r"(?i)(<script[^>]*>.*?</script>|<img[^>]*onerror\s*=|<svg[^>]*onload\s*=)",
        r"(?i)(javascript:|on\w+\s*=)",
        r"(?i)(alert\s*\(|document\.cookie|eval\s*\(|innerHTML)",
        r"(?i)(<iframe|<embed|<object|<body\s+onload)",
    ],
    "Path Traversal": [
        r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|\.\.%252f)",
        r"(?i)(/etc/passwd|/etc/shadow|/proc/self|/windows/system32|boot\.ini)",
    ],
    "Command Injection": [
        r"(?i)(;|\||&|`|\$\(|\${)(ls|cat|id|whoami|pwd|uname|ps|netstat|ifconfig)",
        r"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell|nc\s+-e)",
    ],
    "File Upload Malicioso": [
        r"(?i)(\.php|\.jsp|\.asp|\.aspx|\.sh|\.py|\.pl|\.exe|\.bat|\.cmd)(\s|$|;|&)",
    ],
    "LFI/RFI": [
        r"(?i)(include|require|include_once|require_once).*(\$|%|_GET|_POST|_REQUEST)",
        r"(?i)(file://|php://|data://|expect://|zip://|phar://)",
    ],
    "SSRF": [
        r"(?i)(http://127\.0\.0\.1|http://localhost|http://0\.0\.0\.0|http://169\.254)",
        r"(?i)(file://|gopher://|dict://|ldap://|ftp://)",
    ],
    "XXE": [
        r"(?i)(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC).*\[",
    ],
    "Authentication Bypass": [
        r"(?i)(admin|administrator|root|test|guest)(\s|:|%3a|%7c)(admin|password|123456|test|root)",
        r"(?i)(bypass|skip|ignore).*(auth|login|password)",
    ],
    "CSRF": [
        r"(?i)(csrf|_token|authenticity_token|X-CSRF-Token)",
    ],
    "IDOR": [
        r"(?i)(id|user_id|account_id|uid)\s*=\s*\d+",
    ],
    "Open Redirect": [
        r"(?i)(redirect|return|url|next|goto)\s*=\s*(http|https|//)",
    ],
    "SSTI": [
        r"(?i)(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|#\{.*\})",
    ],
    "XXS en Headers": [
        r"(?i)(X-Forwarded-For|X-Real-IP|User-Agent).*[<>]",
    ],
}

# Vulnerabilidades específicas a buscar
VULNERABILITY_CHECKS = {
    "Exposed Admin Panel": [
        r"(?i)(/admin|/administrator|/wp-admin|/phpmyadmin|/cpanel)",
    ],
    "Sensitive Files": [
        r"(?i)(\.git|\.env|\.htaccess|\.htpasswd|web\.config|config\.php)",
    ],
    "API Endpoints": [
        r"(?i)(/api/|/rest/|/graphql|/v1/|/v2/)",
    ],
    "Backup Files": [
        r"(?i)(\.bak|\.backup|\.old|\.tmp|\.swp|~)",
    ],
}

class AdvancedWebMonitor:
    def __init__(self):
        self.events = []
        self.stats = defaultdict(int)
        self.vulnerability_findings = []
        self.last_update = time.time()
        self.event_queue = queue.Queue()
        self.detect_interface()
        
    def detect_interface(self):
        """Detecta la interfaz de red activa"""
        global INTERFACE
        try:
            result = subprocess.run(['ip', 'route', 'get', TARGET_IP], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r'dev\s+(\w+)', result.stdout)
                if match:
                    INTERFACE = match.group(1)
                    print(f"[+] Interfaz detectada: {INTERFACE}")
                    return
        except:
            pass
        
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            matches = re.findall(r'\d+:\s+(\w+):', result.stdout)
            if matches:
                INTERFACE = matches[0]
                print(f"[+] Usando interfaz: {INTERFACE}")
        except:
            print("[!] No se pudo detectar interfaz, usando 'any'")
            INTERFACE = "any"
    
    def analyze_request(self, request_data, path, method):
        """Análisis profundo de peticiones"""
        detected_attacks = []
        detected_vulns = []
        
        # Analizar ataques
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, request_data) or re.search(pattern, path):
                    detected_attacks.append(attack_type)
                    self.stats[attack_type] += 1
                    break
        
        # Analizar vulnerabilidades
        for vuln_type, patterns in VULNERABILITY_CHECKS.items():
            for pattern in patterns:
                if re.search(pattern, path):
                    detected_vulns.append(vuln_type)
                    break
        
        return detected_attacks, detected_vulns
    
    def parse_http_request(self, packet_data):
        """Extrae información detallada de peticiones HTTP"""
        try:
            method_match = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)', 
                                   packet_data, re.MULTILINE)
            if not method_match:
                return None
            
            method = method_match.group(1)
            path = method_match.group(2)
            
            host_match = re.search(r'Host:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            host = host_match.group(1) if host_match else "Unknown"
            
            ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            user_agent = ua_match.group(1) if ua_match else "Unknown"
            
            referer_match = re.search(r'Referer:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            referer = referer_match.group(1) if referer_match else None
            
            cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            cookies = cookie_match.group(1) if cookie_match else None
            
            # Extraer parámetros POST
            post_data = ""
            if method == "POST":
                post_match = re.search(r'\r\n\r\n(.+)', packet_data, re.DOTALL)
                if post_match:
                    post_data = post_match.group(1)[:500]
            
            return {
                'method': method,
                'path': path,
                'host': host,
                'user_agent': user_agent,
                'referer': referer,
                'cookies': cookies,
                'post_data': post_data,
                'raw': packet_data[:1000]
            }
        except Exception as e:
            return None
    
    def capture_packets(self, duration=30):
        """Captura paquetes HTTP/HTTPS"""
        if not INTERFACE:
            return []
        
        try:
            # Si ya estamos ejecutando como root, no necesitamos sudo
            cmd = [
                'tcpdump',
                '-i', INTERFACE,
                '-A',
                '-s', '0',
                '-n',
                f'host {TARGET_IP} and (port 80 or port 443 or port 8080 or port 8443)',
                '-c', '50'
            ]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, 
                                  text=True, timeout=duration)
            
            if result.returncode != 0:
                return []
            
            packets = []
            current_packet = ""
            
            for line in result.stdout.split('\n'):
                if line.startswith(' ') or line.startswith('\t'):
                    current_packet += line + '\n'
                else:
                    if current_packet and ('HTTP' in current_packet or 'GET' in current_packet or 'POST' in current_packet):
                        packets.append(current_packet)
                    current_packet = line + '\n' if line else ""
            
            if current_packet and ('HTTP' in current_packet or 'GET' in current_packet or 'POST' in current_packet):
                packets.append(current_packet)
            
            return packets
        except subprocess.TimeoutExpired:
            return []
        except Exception as e:
            # No mostrar error si es solo timeout o no hay paquetes
            if "timeout" not in str(e).lower():
                print(f"[!] Error capturando paquetes: {e}")
            return []
    
    def log_event(self, event):
        """Registra evento inmediatamente"""
        log_entry = f"\n{'='*80}\n"
        log_entry += f"TIMESTAMP: {event['timestamp']}\n"
        log_entry += f"IP ORIGEN: {event['src_ip']}\n"
        log_entry += f"MÉTODO: {event['method']}\n"
        log_entry += f"RUTA: {event['path']}\n"
        log_entry += f"HOST: {event['host']}\n"
        log_entry += f"USER-AGENT: {event['user_agent']}\n"
        
        if event.get('referer'):
            log_entry += f"REFERER: {event['referer']}\n"
        
        if event['attacks_detected']:
            log_entry += f"⚠️  ATAQUES DETECTADOS: {', '.join(event['attacks_detected'])}\n"
            log_entry += f"SEVERIDAD: {event['severity']}\n"
        
        if event.get('vulnerabilities'):
            log_entry += f"🔍 VULNERABILIDADES: {', '.join(event['vulnerabilities'])}\n"
        
        if event.get('post_data'):
            log_entry += f"POST DATA: {event['post_data'][:200]}\n"
        
        log_entry += f"{'='*80}\n"
        
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            print(f"[+] {event['timestamp']} - {event['method']} {event['path']} | Ataques: {len(event['attacks_detected'])} | Vulns: {len(event.get('vulnerabilities', []))}")
        except Exception as e:
            print(f"[!] Error escribiendo log: {e}")
    
    def save_log_file(self):
        """Guarda log completo con análisis"""
        try:
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("MONITOR AVANZADO DE SEGURIDAD WEB - milnomes.es\n")
                f.write(f"Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                # Estadísticas
                f.write("ESTADÍSTICAS DE ATAQUES:\n")
                f.write("-"*80 + "\n")
                total_attacks = sum(self.stats.values())
                f.write(f"Total de ataques detectados: {total_attacks}\n\n")
                for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
                    f.write(f"  {attack_type}: {count} ({percentage:.1f}%)\n")
                f.write("\n")
                
                # Análisis de vulnerabilidades
                f.write("ANÁLISIS DE VULNERABILIDADES DETECTADAS:\n")
                f.write("-"*80 + "\n")
                vuln_stats = defaultdict(int)
                for event in self.events:
                    for vuln in event.get('vulnerabilities', []):
                        vuln_stats[vuln] += 1
                
                if vuln_stats:
                    for vuln, count in sorted(vuln_stats.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"  {vuln}: {count} intentos de acceso\n")
                else:
                    f.write("  No se detectaron vulnerabilidades específicas\n")
                f.write("\n")
                
                # Eventos críticos
                critical_events = [e for e in self.events if e['attacks_detected']]
                f.write(f"EVENTOS CRÍTICOS ({len(critical_events)}):\n")
                f.write("-"*80 + "\n")
                for event in critical_events[-50:]:
                    f.write(f"\n[{event['timestamp']}] {event['method']} {event['path']}\n")
                    f.write(f"  IP: {event['src_ip']} | Host: {event['host']}\n")
                    f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks_detected'])}\n")
                    if event.get('vulnerabilities'):
                        f.write(f"  🔍 VULNERABILIDADES: {', '.join(event['vulnerabilities'])}\n")
                    f.write(f"  User-Agent: {event['user_agent'][:100]}\n")
                
                f.write("\n")
                
                # Todos los eventos (últimos 200)
                f.write(f"TODOS LOS EVENTOS (últimos 200 de {len(self.events)}):\n")
                f.write("-"*80 + "\n")
                for event in self.events[-200:]:
                    f.write(f"\n[{event['timestamp']}] {event['method']} {event['path']}\n")
                    f.write(f"  IP: {event['src_ip']} | Host: {event['host']}\n")
                    if event['attacks_detected']:
                        f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks_detected'])}\n")
                    if event.get('vulnerabilities'):
                        f.write(f"  🔍 VULNERABILIDADES: {', '.join(event['vulnerabilities'])}\n")
                
                f.write("\n" + "="*80 + "\n")
            
            print(f"[+] Log completo guardado: {len(self.events)} eventos, {sum(self.stats.values())} ataques")
        except Exception as e:
            print(f"[!] Error guardando log: {e}")
    
    def monitor_web_traffic(self):
        """Monitoreo continuo"""
        print(f"[*] Iniciando monitoreo avanzado de seguridad web...")
        print(f"[*] Objetivo: {TARGET_IP} ({', '.join(TARGET_DOMAINS)})")
        print(f"[*] Archivo de log: {LOG_FILE}")
        print(f"[*] Actualización cada {UPDATE_INTERVAL} segundos\n")
        
        while True:
            try:
                packets = self.capture_packets(duration=30)
                
                for packet in packets:
                    request = self.parse_http_request(packet)
                    if not request:
                        continue
                    
                    if not any(domain in request['host'] for domain in TARGET_DOMAINS):
                        continue
                    
                    attacks, vulns = self.analyze_request(
                        request['raw'] + request['path'], 
                        request['path'], 
                        request['method']
                    )
                    
                    event = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': 'Capturado',  # Se puede mejorar extrayendo IP real
                        'method': request['method'],
                        'path': request['path'],
                        'host': request['host'],
                        'user_agent': request['user_agent'],
                        'referer': request.get('referer'),
                        'post_data': request.get('post_data'),
                        'attacks_detected': attacks,
                        'vulnerabilities': vulns,
                        'severity': 'CRITICAL' if attacks else 'HIGH' if vulns else 'INFO'
                    }
                    
                    self.events.append(event)
                    self.log_event(event)
                
                current_time = time.time()
                if current_time - self.last_update >= UPDATE_INTERVAL:
                    self.save_log_file()
                    self.last_update = current_time
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("\n[*] Deteniendo monitoreo...")
                self.save_log_file()
                self.print_summary()
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                time.sleep(10)
    
    def print_summary(self):
        """Resumen final"""
        print("\n" + "="*80)
        print("RESUMEN DE MONITOREO")
        print("="*80)
        print(f"Total de eventos: {len(self.events)}")
        print(f"Total de ataques: {sum(self.stats.values())}")
        print(f"Eventos críticos: {len([e for e in self.events if e['attacks_detected']])}")
        print("\nTop 5 ataques:")
        for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {attack_type}: {count}")
        print("="*80)

def check_dependencies():
    """Verifica dependencias"""
    missing = []
    try:
        subprocess.run(['which', 'tcpdump'], capture_output=True, check=True)
    except:
        missing.append('tcpdump')
    
    if missing:
        print("[!] Instalar dependencias:")
        print("    sudo apt-get update && sudo apt-get install -y tcpdump")
        return False
    return True

if __name__ == "__main__":
    print("="*80)
    print("MONITOR AVANZADO DE SEGURIDAD WEB - milnomes.es")
    print("="*80)
    
    if not check_dependencies():
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("[!] Requiere permisos root")
        print("[*] Ejecutar: sudo python3 web_monitor_advanced.py")
        sys.exit(1)
    
    monitor = AdvancedWebMonitor()
    monitor.monitor_web_traffic()

