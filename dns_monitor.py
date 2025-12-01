#!/usr/bin/env python3
"""
Monitor de Eventos DNS
Monitorea consultas DNS relacionadas con milnomes.es (10.104.0.19)
"""

import subprocess
import re
import time
from datetime import datetime
from collections import defaultdict
import os
import sys

# Configuración
TARGET_DOMAIN = "milnomes.es"
TARGET_IP = "10.104.0.19"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_events_log.txt")
UPDATE_INTERVAL = 300  # 5 minutos
INTERFACE = None

# Patrones de ataques DNS
DNS_ATTACK_PATTERNS = {
    "DNS Tunneling": [
        r"(?i)([a-z0-9]{50,}\.milnomes\.es)",  # Subdominios muy largos
        r"(?i)([a-f0-9]{32,}\.milnomes\.es)",  # Hex encoding
    ],
    "DNS Exfiltration": [
        r"(?i)([a-z0-9]{20,}\.milnomes\.es)",  # Subdominios largos sospechosos
    ],
    "Subdomain Enumeration": [
        r"(?i)(admin|administrator|test|dev|staging|backup|old|www|mail|ftp|ssh|vpn|api|db|mysql|phpmyadmin|wp-admin|adminer|phpinfo|cpanel|plesk|webmin|zabbix|nagios|grafana|kibana|jenkins|gitlab|jira|confluence|redmine|git|repo|repository|secure|ssl|tls|remote|access|control|panel|monitoring|elastic|bitbucket|svn|cvs|hg|bzr|code|source|src|build|ci|cd|deploy|deployment|release|qa|quality|assurance|testing|unit|integration|performance|load|stress|security|penetration|vulnerability|scan|audit|compliance|restore|archive|legacy|deprecated|obsolete|unused|disabled|enabled|active|inactive|maintenance|down|up|online|offline|status|health|ping|monitor|check|verify|validate|demo|sample|example|template|default|custom|user|users|account|accounts|profile|profiles|settings|config|configuration|setup|install|installation|update|upgrade|patch|fix|bug|issue|ticket|support|help|faq|documentation|docs|wiki|blog|news|forum|community|contact|about|privacy|terms|legal|cookie|policy|sitemap|robots|license|credits|donate|sponsor|partner|affiliate|advertise|ads|banner|popup|tracker|analytics|stats|statistics|metrics|logging|logs|error|errors|exception|exceptions|debug|debugging|trace|tracing|profiling|optimization|cache|caching|cdn|network|edge|origin|mirror|backups|replica|cluster|node|server|host|machine|vm|container|docker|kubernetes|k8s|redis|memcached|mongodb|postgresql|mariadb|oracle|sqlserver|sqlite|influxdb|prometheus|elasticsearch|solr|splunk|logstash)\.milnomes\.es",
    ],
    "DNS Amplification": [
        r"(?i)(ANY|AXFR|IXFR)",
    ],
    "DNS Cache Poisoning": [
        r"(?i)(\.milnomes\.es.*IN.*A.*[^10\.104\.0\.19])",
    ],
}

class DNSMonitor:
    def __init__(self):
        self.events = []
        self.stats = defaultdict(int)
        self.query_stats = defaultdict(int)
        self.last_update = time.time()
        self.detect_interface()
    
    def detect_interface(self):
        """Detecta la interfaz de red activa"""
        global INTERFACE
        try:
            result = subprocess.run(['ip', 'route', 'get', TARGET_IP], 
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, timeout=5)
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
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, timeout=5)
            matches = re.findall(r'\d+:\s+(\w+):', result.stdout)
            if matches:
                INTERFACE = matches[0]
                print(f"[+] Usando interfaz: {INTERFACE}")
        except:
            print("[!] No se pudo detectar interfaz, usando 'any'")
            INTERFACE = "any"
    
    def analyze_dns_query(self, query_data):
        """Analiza una consulta DNS en busca de patrones sospechosos"""
        detected_attacks = []
        
        for attack_type, patterns in DNS_ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, query_data):
                    detected_attacks.append(attack_type)
                    self.stats[attack_type] += 1
                    break
        
        return detected_attacks
    
    def parse_dns_packet(self, packet_data):
        """Extrae información de un paquete DNS"""
        try:
            # Buscar consulta DNS
            query_match = re.search(r'(?:A\?|AAAA\?|CNAME\?|MX\?|TXT\?|NS\?|PTR\?|SOA\?|SRV\?|ANY\?)\s+([^\s\.]+\.milnomes\.es)', packet_data, re.IGNORECASE)
            if not query_match:
                # Intentar otro formato
                query_match = re.search(r'([a-zA-Z0-9\-_\.]+\.milnomes\.es)', packet_data)
            
            if not query_match:
                return None
            
            domain = query_match.group(1)
            
            # Buscar tipo de consulta
            qtype_match = re.search(r'(A|AAAA|CNAME|MX|TXT|NS|PTR|SOA|SRV|ANY)\?', packet_data, re.IGNORECASE)
            qtype = qtype_match.group(1).upper() if qtype_match else "A"
            
            # Buscar IP origen
            ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)', packet_data)
            src_ip = ip_match.group(1) if ip_match else "Unknown"
            
            # Buscar respuesta
            response_match = re.search(r'(?:A|AAAA)\s+(\d+\.\d+\.\d+\.\d+)', packet_data)
            response_ip = response_match.group(1) if response_match else None
            
            # Buscar flags
            is_query = "qr" not in packet_data.lower() or "standard query" in packet_data.lower()
            is_response = "qr" in packet_data.lower() and "response" in packet_data.lower()
            
            return {
                'domain': domain,
                'qtype': qtype,
                'src_ip': src_ip,
                'response_ip': response_ip,
                'is_query': is_query,
                'is_response': is_response,
                'raw': packet_data[:500]
            }
        except Exception as e:
            return None
    
    def capture_dns_packets(self, duration=30):
        """Captura paquetes DNS"""
        if not INTERFACE:
            return []
        
        try:
            cmd = [
                'tcpdump',
                '-i', INTERFACE,
                '-A',
                '-s', '0',
                '-n',
                f'port 53 and (host {TARGET_IP} or milnomes.es)',
                '-c', '100'
            ]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, timeout=duration)
            
            if result.returncode != 0:
                return []
            
            packets = []
            current_packet = ""
            
            for line in result.stdout.split('\n'):
                if line.startswith(' ') or line.startswith('\t') or 'DNS' in line.upper():
                    current_packet += line + '\n'
                else:
                    if current_packet and ('DNS' in current_packet.upper() or 'milnomes.es' in current_packet):
                        packets.append(current_packet)
                    current_packet = line + '\n' if line else ""
            
            if current_packet and ('DNS' in current_packet.upper() or 'milnomes.es' in current_packet):
                packets.append(current_packet)
            
            return packets
        except subprocess.TimeoutExpired:
            return []
        except Exception as e:
            if "timeout" not in str(e).lower():
                print(f"[!] Error capturando paquetes DNS: {e}")
            return []
    
    def log_event(self, event):
        """Registra un evento DNS inmediatamente"""
        log_entry = f"\n{'='*80}\n"
        log_entry += f"TIMESTAMP: {event['timestamp']}\n"
        log_entry += f"TIPO: {'CONSULTA' if event['is_query'] else 'RESPUESTA'}\n"
        log_entry += f"DOMINIO: {event['domain']}\n"
        log_entry += f"TIPO DNS: {event['qtype']}\n"
        log_entry += f"IP ORIGEN: {event['src_ip']}\n"
        
        if event.get('response_ip'):
            log_entry += f"IP RESPUESTA: {event['response_ip']}\n"
        
        if event['attacks_detected']:
            log_entry += f"⚠️  ATAQUES DETECTADOS: {', '.join(event['attacks_detected'])}\n"
            log_entry += f"SEVERIDAD: {event['severity']}\n"
        
        log_entry += f"{'='*80}\n"
        
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            print(f"[+] {event['timestamp']} - {event['qtype']} {event['domain']} | Ataques: {len(event['attacks_detected'])}")
        except Exception as e:
            print(f"[!] Error escribiendo log: {e}")
    
    def save_log_file(self):
        """Guarda el log completo con estadísticas"""
        try:
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("MONITOR DE EVENTOS DNS - milnomes.es\n")
                f.write(f"Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                # Estadísticas de ataques
                f.write("ESTADÍSTICAS DE ATAQUES DNS:\n")
                f.write("-"*80 + "\n")
                total_attacks = sum(self.stats.values())
                f.write(f"Total de ataques detectados: {total_attacks}\n\n")
                for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
                    f.write(f"  {attack_type}: {count} ({percentage:.1f}%)\n")
                f.write("\n")
                
                # Estadísticas de tipos de consulta
                f.write("ESTADÍSTICAS DE TIPOS DE CONSULTA:\n")
                f.write("-"*80 + "\n")
                for qtype, count in sorted(self.query_stats.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {qtype}: {count}\n")
                f.write("\n")
                
                # Eventos con ataques
                attack_events = [e for e in self.events if e['attacks_detected']]
                f.write(f"EVENTOS CON ATAQUES ({len(attack_events)}):\n")
                f.write("-"*80 + "\n")
                for event in attack_events[-50:]:
                    f.write(f"\n[{event['timestamp']}] {event['qtype']} {event['domain']}\n")
                    f.write(f"  IP: {event['src_ip']} | Tipo: {'CONSULTA' if event['is_query'] else 'RESPUESTA'}\n")
                    f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks_detected'])}\n")
                    if event.get('response_ip'):
                        f.write(f"  IP Respuesta: {event['response_ip']}\n")
                
                f.write("\n")
                
                # Todos los eventos (últimos 200)
                f.write(f"TODOS LOS EVENTOS (últimos 200 de {len(self.events)}):\n")
                f.write("-"*80 + "\n")
                for event in self.events[-200:]:
                    f.write(f"\n[{event['timestamp']}] {event['qtype']} {event['domain']}\n")
                    f.write(f"  IP: {event['src_ip']} | Tipo: {'CONSULTA' if event['is_query'] else 'RESPUESTA'}\n")
                    if event['attacks_detected']:
                        f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks_detected'])}\n")
                    if event.get('response_ip'):
                        f.write(f"  IP Respuesta: {event['response_ip']}\n")
                
                f.write("\n" + "="*80 + "\n")
            
            print(f"[+] Log DNS guardado: {len(self.events)} eventos, {sum(self.stats.values())} ataques")
        except Exception as e:
            print(f"[!] Error guardando log: {e}")
    
    def monitor_dns_traffic(self):
        """Monitorea el tráfico DNS continuamente"""
        print(f"[*] Iniciando monitoreo de eventos DNS...")
        print(f"[*] Dominio objetivo: {TARGET_DOMAIN}")
        print(f"[*] IP objetivo: {TARGET_IP}")
        print(f"[*] Archivo de log: {LOG_FILE}")
        print(f"[*] Actualización cada {UPDATE_INTERVAL} segundos\n")
        
        while True:
            try:
                packets = self.capture_dns_packets(duration=30)
                
                for packet in packets:
                    dns_info = self.parse_dns_packet(packet)
                    if not dns_info:
                        continue
                    
                    # Analizar en busca de ataques
                    attacks = self.analyze_dns_query(dns_info['domain'] + " " + dns_info['raw'])
                    
                    # Actualizar estadísticas de tipo de consulta
                    self.query_stats[dns_info['qtype']] += 1
                    
                    event = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'domain': dns_info['domain'],
                        'qtype': dns_info['qtype'],
                        'src_ip': dns_info['src_ip'],
                        'response_ip': dns_info.get('response_ip'),
                        'is_query': dns_info['is_query'],
                        'is_response': dns_info['is_response'],
                        'attacks_detected': attacks,
                        'severity': 'CRITICAL' if attacks else 'INFO'
                    }
                    
                    self.events.append(event)
                    self.log_event(event)
                
                current_time = time.time()
                if current_time - self.last_update >= UPDATE_INTERVAL:
                    self.save_log_file()
                    self.last_update = current_time
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("\n[*] Deteniendo monitoreo DNS...")
                self.save_log_file()
                self.print_summary()
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                time.sleep(10)
    
    def print_summary(self):
        """Resumen final"""
        print("\n" + "="*80)
        print("RESUMEN DE MONITOREO DNS")
        print("="*80)
        print(f"Total de eventos: {len(self.events)}")
        print(f"Total de ataques: {sum(self.stats.values())}")
        print(f"Eventos críticos: {len([e for e in self.events if e['attacks_detected']])}")
        print("\nTop 5 ataques:")
        for attack_type, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {attack_type}: {count}")
        print("\nTipos de consulta más frecuentes:")
        for qtype, count in sorted(self.query_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {qtype}: {count}")
        print("="*80)

def check_dependencies():
    """Verifica dependencias"""
    missing = []
    try:
        subprocess.run(['which', 'tcpdump'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    except:
        missing.append('tcpdump')
    
    if missing:
        print("[!] Instalar dependencias:")
        print("    sudo apt-get update && sudo apt-get install -y tcpdump")
        return False
    return True

if __name__ == "__main__":
    print("="*80)
    print("MONITOR DE EVENTOS DNS - milnomes.es")
    print("="*80)
    
    if not check_dependencies():
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("[!] Requiere permisos root")
        print("[*] Ejecutar: sudo python3 dns_monitor.py")
        sys.exit(1)
    
    monitor = DNSMonitor()
    monitor.monitor_dns_traffic()

