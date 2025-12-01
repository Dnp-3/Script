#!/usr/bin/env python3
"""
Analizador de Logs de Servidor Web
Analiza logs de Apache/Nginx en busca de ataques y vulnerabilidades
"""

import re
import os
import sys
from datetime import datetime
from collections import defaultdict

# Rutas comunes de logs
LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
]

# Obtener directorio del script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "web_attacks_log.txt")

# Patrones de ataques
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
        r"(?i)(or\s+1\s*=\s*1|admin'--|' or '1'='1)",
    ],
    "XSS": [
        r"(?i)(<script|javascript:|onerror\s*=|alert\s*\()",
    ],
    "Path Traversal": [
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)",
    ],
    "Command Injection": [
        r"(?i)(;|\||&)(ls|cat|id|whoami|cmd\.exe)",
    ],
    "LFI/RFI": [
        r"(?i)(include|require|file://|php://)",
    ],
    "SSRF": [
        r"(?i)(http://127\.0\.0\.1|http://localhost|file://)",
    ],
}

def parse_apache_log(line):
    """Parsea formato de log de Apache"""
    # Formato común: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
    pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line)
    if match:
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'method': match.group(3),
            'path': match.group(4),
            'protocol': match.group(5),
            'status': match.group(6),
            'size': match.group(7),
            'referer': match.group(8),
            'user_agent': match.group(9),
            'raw': line
        }
    return None

def parse_nginx_log(line):
    """Parsea formato de log de Nginx"""
    # Similar a Apache
    return parse_apache_log(line)

def analyze_line(log_entry):
    """Analiza una línea de log en busca de ataques"""
    if not log_entry:
        return []
    
    attacks = []
    path = log_entry.get('path', '')
    user_agent = log_entry.get('user_agent', '')
    referer = log_entry.get('referer', '')
    raw = log_entry.get('raw', '')
    
    search_text = f"{path} {user_agent} {referer} {raw}"
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, search_text):
                attacks.append(attack_type)
                break
    
    return attacks

def find_log_files():
    """Encuentra archivos de log disponibles"""
    found = []
    for path in LOG_PATHS:
        if os.path.exists(path) and os.access(path, os.R_OK):
            found.append(path)
    return found

def analyze_log_file(log_path):
    """Analiza un archivo de log"""
    print(f"[*] Analizando: {log_path}")
    
    events = []
    stats = defaultdict(int)
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Intentar parsear como Apache/Nginx
                log_entry = parse_apache_log(line) or parse_nginx_log(line)
                
                if log_entry:
                    attacks = analyze_line(log_entry)
                    
                    if attacks or True:  # Registrar todos
                        event = {
                            'timestamp': log_entry.get('timestamp', 'Unknown'),
                            'ip': log_entry.get('ip', 'Unknown'),
                            'method': log_entry.get('method', 'Unknown'),
                            'path': log_entry.get('path', 'Unknown'),
                            'status': log_entry.get('status', 'Unknown'),
                            'user_agent': log_entry.get('user_agent', 'Unknown'),
                            'attacks': attacks,
                            'source_file': log_path,
                            'line': line_num
                        }
                        events.append(event)
                        
                        for attack in attacks:
                            stats[attack] += 1
                
    except PermissionError:
        print(f"[!] Sin permisos para leer: {log_path}")
        print(f"[*] Intentar con: sudo python3 {sys.argv[0]}")
    except Exception as e:
        print(f"[!] Error leyendo {log_path}: {e}")
    
    return events, stats

def main():
    print("="*80)
    print("Analizador de Logs de Servidor Web")
    print("="*80)
    print()
    
    log_files = find_log_files()
    
    if not log_files:
        print("[!] No se encontraron archivos de log accesibles")
        print("[*] Rutas buscadas:")
        for path in LOG_PATHS:
            print(f"    - {path}")
        print()
        print("[*] Si los logs están en otra ubicación, edita LOG_PATHS en el script")
        return
    
    print(f"[+] Encontrados {len(log_files)} archivo(s) de log:")
    for log_file in log_files:
        print(f"    - {log_file}")
    print()
    
    all_events = []
    all_stats = defaultdict(int)
    
    for log_file in log_files:
        events, stats = analyze_log_file(log_file)
        all_events.extend(events)
        for attack, count in stats.items():
            all_stats[attack] += count
    
    # Guardar resultados
    print(f"\n[*] Guardando resultados en: {OUTPUT_FILE}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("ANÁLISIS DE LOGS DE SERVIDOR WEB\n")
        f.write(f"Fecha de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")
        
        # Estadísticas
        f.write("ESTADÍSTICAS DE ATAQUES:\n")
        f.write("-"*80 + "\n")
        total = sum(all_stats.values())
        f.write(f"Total de ataques detectados: {total}\n\n")
        for attack, count in sorted(all_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            f.write(f"  {attack}: {count} ({percentage:.1f}%)\n")
        f.write("\n")
        
        # Eventos con ataques
        attack_events = [e for e in all_events if e['attacks']]
        f.write(f"EVENTOS CON ATAQUES ({len(attack_events)}):\n")
        f.write("-"*80 + "\n")
        for event in attack_events[:100]:  # Primeros 100
            f.write(f"\n[{event['timestamp']}] {event['method']} {event['path']}\n")
            f.write(f"  IP: {event['ip']} | Status: {event['status']}\n")
            f.write(f"  ⚠️  ATAQUES: {', '.join(event['attacks'])}\n")
            f.write(f"  User-Agent: {event['user_agent'][:100]}\n")
            f.write(f"  Archivo: {event['source_file']}:{event['line']}\n")
        
        f.write("\n" + "="*80 + "\n")
    
    print(f"[+] Análisis completado:")
    print(f"    - Total de eventos: {len(all_events)}")
    print(f"    - Eventos con ataques: {len(attack_events)}")
    print(f"    - Total de ataques: {total}")
    print()

if __name__ == "__main__":
    main()

