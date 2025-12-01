#!/usr/bin/env python3
"""
Script de Monitoreo de Seguridad Web
Monitorea ataques y eventos web hacia milnomes.es y nadieentiendemiletra.milnomes.es
IP objetivo: 10.104.0.19
"""

import subprocess
import re
import json
import time
from datetime import datetime
from collections import defaultdict
import os
import sys

# Configuración
TARGET_IP = "10.104.0.19"
TARGET_DOMAINS = ["milnomes.es", "nadieentiendemiletra.milnomes.es"]
# Obtener directorio del script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "web_attacks_log.txt")
UPDATE_INTERVAL = 300  # 5 minutos en segundos
INTERFACE = None  # Se detectará automáticamente

# Patrones de ataques comunes
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|exec\s*\(|';\s*(--|#|/\*))",
        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
        r"(?i)(admin'--|admin'#|' or '1'='1|' or 1=1--)",
    ],
    "XSS (Cross-Site Scripting)": [
        r"(?i)(<script[^>]*>.*?</script>|<img[^>]*onerror\s*=|<svg[^>]*onload\s*=)",
        r"(?i)(javascript:|on\w+\s*=)",
        r"(?i)(alert\s*\(|document\.cookie|eval\s*\()",
    ],
    "Path Traversal": [
        r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c)",
        r"(?i)(/etc/passwd|/etc/shadow|/proc/self|/windows/system32)",
    ],
    "Command Injection": [
        r"(?i)(;|\||&|`|\$\(|\${)(ls|cat|id|whoami|pwd|uname|ps|netstat)",
        r"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell)",
    ],
    "File Upload": [
        r"(?i)(\.php|\.jsp|\.asp|\.aspx|\.sh|\.py|\.pl)(\s|$|;|&)",
    ],
    "LFI/RFI": [
        r"(?i)(include|require|include_once|require_once).*(\$|%|_GET|_POST|_REQUEST)",
        r"(?i)(file://|php://|data://|expect://|zip://)",
    ],
    "SSRF": [
        r"(?i)(http://127\.0\.0\.1|http://localhost|http://0\.0\.0\.0|http://169\.254)",
        r"(?i)(file://|gopher://|dict://|ldap://)",
    ],
    "XXE": [
        r"(?i)(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC).*\[",
    ],
    "Authentication Bypass": [
        r"(?i)(admin|administrator|root|test|guest)(\s|:|%3a|%7c)(admin|password|123456|test)",
    ],
    "CSRF": [
        r"(?i)(csrf|_token|authenticity_token)",
    ],
}

class WebSecurityMonitor:
    def __init__(self):
        self.events = []
        self.stats = defaultdict(int)
        self.last_update = time.time()
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
        
        # Fallback: usar la primera interfaz activa
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
    
    def analyze_request(self, request_data):
        """Analiza una petición HTTP en busca de patrones de ataque"""
        detected_attacks = []
        
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, request_data):
                    detected_attacks.append(attack_type)
                    self.stats[attack_type] += 1
                    break
        
        return detected_attacks
    
    def parse_http_request(self, packet_data):
        """Extrae información de una petición HTTP"""
        try:
            # Buscar método HTTP
            method_match = re.search(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)', 
                                   packet_data, re.MULTILINE)
            if not method_match:
                return None
            
            method = method_match.group(1)
            path = method_match.group(2)
            
            # Buscar Host header
            host_match = re.search(r'Host:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            host = host_match.group(1) if host_match else "Unknown"
            
            # Buscar User-Agent
            ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', packet_data, re.IGNORECASE)
            user_agent = ua_match.group(1) if ua_match else "Unknown"
            
            # Buscar IP origen (si está disponible en el contexto)
            ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)', packet_data)
            src_ip = ip_match.group(1) if ip_match else "Unknown"
            
            return {
                'method': method,
                'path': path,
                'host': host,
                'user_agent': user_agent,
                'src_ip': src_ip,
                'raw': packet_data[:500]  # Primeros 500 caracteres
            }
        except Exception as e:
            return None
    
    def capture_packets(self, duration=60):
        """Captura paquetes HTTP usando tcpdump"""
        if not INTERFACE:
            print("[!] No hay interfaz disponible")
            return []
        
        try:
            # Comando tcpdump para capturar HTTP hacia la IP objetivo
            # Si ya estamos ejecutando como root, no necesitamos sudo
            cmd = [
                'tcpdump',
                '-i', INTERFACE,
                '-A',  # ASCII output
                '-s', '0',  # Capturar paquetes completos
                '-n',  # No resolver nombres
                f'host {TARGET_IP} and (port 80 or port 443 or port 8080)',
                '-c', '100'  # Máximo 100 paquetes por captura
            ]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, 
                                  text=True, timeout=duration)
            
            if result.returncode != 0:
                return []
            
            # Parsear paquetes HTTP
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
    
    def monitor_web_traffic(self):
        """Monitorea el tráfico web continuamente"""
        print(f"[*] Iniciando monitoreo de seguridad web...")
        print(f"[*] Objetivo: {TARGET_IP} ({', '.join(TARGET_DOMAINS)})")
        print(f"[*] Archivo de log: {LOG_FILE}")
        print(f"[*] Actualización cada {UPDATE_INTERVAL} segundos\n")
        
        while True:
            try:
                # Capturar paquetes
                packets = self.capture_packets(duration=30)
                
                for packet in packets:
                    # Parsear petición HTTP
                    request = self.parse_http_request(packet)
                    if not request:
                        continue
                    
                    # Verificar si es hacia nuestros dominios
                    if not any(domain in request['host'] for domain in TARGET_DOMAINS):
                        continue
                    
                    # Analizar en busca de ataques
                    attacks = self.analyze_request(request['raw'])
                    
                    if attacks or True:  # Registrar todos los eventos
                        event = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'src_ip': request['src_ip'],
                            'method': request['method'],
                            'path': request['path'],
                            'host': request['host'],
                            'user_agent': request['user_agent'],
                            'attacks_detected': attacks,
                            'severity': 'HIGH' if attacks else 'INFO'
                        }
                        
                        self.events.append(event)
                        self.log_event(event)
                
                # Guardar log completo cada UPDATE_INTERVAL segundos
                current_time = time.time()
                if current_time - self.last_update >= UPDATE_INTERVAL:
                    self.save_log_file()
                    self.last_update = current_time
                
                time.sleep(5)  # Esperar 5 segundos entre capturas
                
            except KeyboardInterrupt:
                print("\n[*] Deteniendo monitoreo...")
                self.save_log_file()
                self.print_summary()
                break
            except Exception as e:
                print(f"[!] Error en monitoreo: {e}")
                time.sleep(10)
    
    def log_event(self, event):
        """Registra un evento inmediatamente"""
        log_entry = f"\n{'='*80}\n"
        log_entry += f"TIMESTAMP: {event['timestamp']}\n"
        log_entry += f"IP ORIGEN: {event['src_ip']}\n"
        log_entry += f"MÉTODO: {event['method']}\n"
        log_entry += f"RUTA: {event['path']}\n"
        log_entry += f"HOST: {event['host']}\n"
        log_entry += f"USER-AGENT: {event['user_agent']}\n"
        
        if event['attacks_detected']:
            log_entry += f"⚠️  ATAQUES DETECTADOS: {', '.join(event['attacks_detected'])}\n"
            log_entry += f"SEVERIDAD: {event['severity']}\n"
        else:
            log_entry += f"TIPO: Evento normal\n"
        
        log_entry += f"{'='*80}\n"
        
        # Escribir inmediatamente al archivo
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            print(f"[+] Evento registrado: {event['method']} {event['path']} - {len(event['attacks_detected'])} ataques detectados")
        except Exception as e:
            print(f"[!] Error escribiendo log: {e}")
    
    def save_log_file(self):
        """Guarda el log completo y estadísticas"""
        try:
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("MONITOR DE SEGURIDAD WEB - milnomes.es\n")
                f.write(f"Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                # Estadísticas
                f.write("ESTADÍSTICAS DE ATAQUES DETECTADOS:\n")
                f.write("-"*80 + "\n")
                for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {attack_type}: {count}\n")
                f.write("\n")
                
                # Eventos recientes (últimos 100)
                f.write("EVENTOS RECIENTES (últimos 100):\n")
                f.write("-"*80 + "\n")
                for event in self.events[-100:]:
                    f.write(f"\n[{event['timestamp']}] {event['method']} {event['path']}\n")
                    f.write(f"  IP: {event['src_ip']} | Host: {event['host']}\n")
                    if event['attacks_detected']:
                        f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks_detected'])}\n")
                    f.write(f"  User-Agent: {event['user_agent'][:80]}\n")
                
                f.write("\n" + "="*80 + "\n")
            
            print(f"[+] Log guardado: {len(self.events)} eventos totales")
        except Exception as e:
            print(f"[!] Error guardando log: {e}")
    
    def print_summary(self):
        """Imprime un resumen de estadísticas"""
        print("\n" + "="*80)
        print("RESUMEN DE MONITOREO")
        print("="*80)
        print(f"Total de eventos: {len(self.events)}")
        print(f"Total de ataques detectados: {sum(self.stats.values())}")
        print("\nTipos de ataques:")
        for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {attack_type}: {count}")
        print("="*80)

def check_dependencies():
    """Verifica que las dependencias estén instaladas"""
    missing = []
    
    # Verificar tcpdump
    try:
        subprocess.run(['which', 'tcpdump'], capture_output=True, check=True)
    except:
        missing.append('tcpdump')
    
    if missing:
        print("[!] Dependencias faltantes:")
        for dep in missing:
            print(f"    - {dep}")
        print("\nInstalar con:")
        print("    sudo apt-get update && sudo apt-get install -y tcpdump")
        return False
    
    return True

if __name__ == "__main__":
    print("="*80)
    print("MONITOR DE SEGURIDAD WEB - milnomes.es")
    print("="*80)
    
    if not check_dependencies():
        sys.exit(1)
    
    # Verificar permisos sudo
    if os.geteuid() != 0:
        print("[!] Este script requiere permisos de root (sudo)")
        print("[*] Ejecutar con: sudo python3 web_monitor.py")
        sys.exit(1)
    
    monitor = WebSecurityMonitor()
    monitor.monitor_web_traffic()

