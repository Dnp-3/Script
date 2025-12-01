#!/usr/bin/env python3
"""
Script de Prueba de Ataques DNS
Simula varios tipos de ataques DNS para probar el monitor dns_monitor.py
SOLO PARA PRUEBAS Y VALIDACIÓN DEL SISTEMA DE MONITOREO
"""

import subprocess
import time
import random
import string
from datetime import datetime

TARGET_DOMAIN = "milnomes.es"

def print_section(title):
    """Imprime un separador visual"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def dns_query(domain, qtype="A"):
    """Realiza una consulta DNS"""
    try:
        cmd = ['dig', '+short', qtype, domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        try:
            # Fallback a host si dig no está disponible
            cmd = ['host', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

def test_normal_queries():
    """Prueba consultas DNS normales"""
    print_section("1. CONSULTAS DNS NORMALES (No deberían detectarse como ataque)")
    
    normal_domains = [
        "milnomes.es",
        "www.milnomes.es",
        "mail.milnomes.es",
    ]
    
    for domain in normal_domains:
        print(f"[*] Consultando: {domain}")
        dns_query(domain)
        time.sleep(0.5)
    
    print("\n[+] Consultas normales completadas\n")

def test_subdomain_enumeration():
    """Simula enumeración de subdominios"""
    print_section("2. SUBDOMAIN ENUMERATION (Debería detectarse como ataque)")
    
    suspicious_subdomains = [
        "admin.milnomes.es",
        "administrator.milnomes.es",
        "test.milnomes.es",
        "dev.milnomes.es",
        "staging.milnomes.es",
        "backup.milnomes.es",
        "phpmyadmin.milnomes.es",
        "cpanel.milnomes.es",
        "webmin.milnomes.es",
        "zabbix.milnomes.es",
        "grafana.milnomes.es",
        "jenkins.milnomes.es",
        "gitlab.milnomes.es",
        "jira.milnomes.es",
        "confluence.milnomes.es",
        "api.milnomes.es",
        "db.milnomes.es",
        "mysql.milnomes.es",
        "secure.milnomes.es",
        "vpn.milnomes.es",
        "remote.milnomes.es",
        "access.milnomes.es",
        "control.milnomes.es",
        "panel.milnomes.es",
        "monitoring.milnomes.es",
        "elastic.milnomes.es",
        "git.milnomes.es",
        "repo.milnomes.es",
        "repository.milnomes.es",
        "code.milnomes.es",
        "source.milnomes.es",
        "build.milnomes.es",
        "ci.milnomes.es",
        "deploy.milnomes.es",
        "staging.milnomes.es",
        "security.milnomes.es",
        "penetration.milnomes.es",
        "vulnerability.milnomes.es",
        "scan.milnomes.es",
        "audit.milnomes.es",
    ]
    
    print(f"[*] Realizando {len(suspicious_subdomains)} consultas de enumeración...")
    
    for i, subdomain in enumerate(suspicious_subdomains, 1):
        print(f"[{i}/{len(suspicious_subdomains)}] Consultando: {subdomain}")
        dns_query(subdomain)
        time.sleep(0.3)  # Pequeña pausa entre consultas
    
    print("\n[+] Enumeración de subdominios completada\n")

def test_dns_tunneling():
    """Simula DNS tunneling con subdominios muy largos"""
    print_section("3. DNS TUNNELING (Debería detectarse como ataque)")
    
    print("[*] Generando subdominios largos para tunneling...")
    
    # Subdominios con más de 50 caracteres (patrón de tunneling)
    tunneling_domains = [
        # Subdominio largo con caracteres alfanuméricos
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=60)) + ".milnomes.es",
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=70)) + ".milnomes.es",
        ''.join(random.choices(string.ascii_lowercase + string.digits, k=80)) + ".milnomes.es",
        
        # Subdominio con encoding hexadecimal (32+ caracteres hex)
        ''.join(random.choices('0123456789abcdef', k=40)) + ".milnomes.es",
        ''.join(random.choices('0123456789abcdef', k=50)) + ".milnomes.es",
        ''.join(random.choices('0123456789abcdef', k=64)) + ".milnomes.es",
        
        # Simulación de datos codificados
        "a" * 60 + ".milnomes.es",
        "0" * 50 + ".milnomes.es",
        "deadbeef" * 8 + ".milnomes.es",  # 64 caracteres hex
    ]
    
    for i, domain in enumerate(tunneling_domains, 1):
        print(f"[{i}/{len(tunneling_domains)}] Consultando tunneling: {domain[:50]}...")
        dns_query(domain)
        time.sleep(0.5)
    
    print("\n[+] Pruebas de DNS tunneling completadas\n")

def test_dns_exfiltration():
    """Simula exfiltración de datos vía DNS"""
    print_section("4. DNS EXFILTRATION (Debería detectarse como ataque)")
    
    print("[*] Simulando exfiltración de datos...")
    
    # Subdominios largos que simulan datos exfiltrados (20+ caracteres)
    exfiltration_domains = [
        "datosconfidenciales123456789.milnomes.es",
        "passwordhash123456789012.milnomes.es",
        "token123456789012345678.milnomes.es",
        "secretkey12345678901234.milnomes.es",
        "apikey12345678901234567.milnomes.es",
        "sessionid123456789012345.milnomes.es",
        "creditcard1234567890123.milnomes.es",
        "ssn1234567890123456789.milnomes.es",
        "email123456789012345678.milnomes.es",
        "documento1234567890123.milnomes.es",
    ]
    
    for i, domain in enumerate(exfiltration_domains, 1):
        print(f"[{i}/{len(exfiltration_domains)}] Consultando exfiltración: {domain}")
        dns_query(domain)
        time.sleep(0.4)
    
    print("\n[+] Pruebas de exfiltración completadas\n")

def test_dns_amplification():
    """Simula ataques de amplificación DNS"""
    print_section("5. DNS AMPLIFICATION (Debería detectarse como ataque)")
    
    print("[*] Realizando consultas de amplificación...")
    
    amplification_queries = [
        ("milnomes.es", "ANY"),
        ("www.milnomes.es", "ANY"),
        ("mail.milnomes.es", "ANY"),
        ("milnomes.es", "AXFR"),
        ("milnomes.es", "IXFR"),
    ]
    
    for i, (domain, qtype) in enumerate(amplification_queries, 1):
        print(f"[{i}/{len(amplification_queries)}] Consultando {qtype}: {domain}")
        dns_query(domain, qtype)
        time.sleep(0.5)
    
    print("\n[+] Pruebas de amplificación completadas\n")

def test_massive_queries():
    """Realiza múltiples consultas rápidas para probar el monitoreo continuo"""
    print_section("6. CONSULTAS MASIVAS (Prueba de rendimiento del monitor)")
    
    print("[*] Realizando 50 consultas rápidas...")
    
    base_subdomains = ["test", "dev", "admin", "api", "db", "mail", "www", "ftp", "ssh", "vpn"]
    
    for i in range(50):
        subdomain = random.choice(base_subdomains) + str(random.randint(1, 1000))
        domain = f"{subdomain}.milnomes.es"
        print(f"[{i+1}/50] Consultando: {domain}")
        dns_query(domain)
        time.sleep(0.2)
    
    print("\n[+] Consultas masivas completadas\n")

def test_mixed_attacks():
    """Mezcla diferentes tipos de ataques"""
    print_section("7. ATAQUES MIXTOS (Simulación realista)")
    
    print("[*] Simulando secuencia de ataques mixtos...")
    
    attacks = [
        ("admin.milnomes.es", "Subdomain Enumeration"),
        ("".join(random.choices(string.ascii_lowercase + string.digits, k=55)) + ".milnomes.es", "DNS Tunneling"),
        ("datos123456789012345678.milnomes.es", "DNS Exfiltration"),
        ("test.milnomes.es", "Subdomain Enumeration"),
        ("milnomes.es", "ANY", "DNS Amplification"),
        ("phpmyadmin.milnomes.es", "Subdomain Enumeration"),
        ("".join(random.choices('0123456789abcdef', k=40)) + ".milnomes.es", "DNS Tunneling"),
    ]
    
    for i, attack in enumerate(attacks, 1):
        if len(attack) == 3:
            domain, attack_type, qtype = attack
            print(f"[{i}/{len(attacks)}] {attack_type}: {domain} (tipo: {qtype})")
            dns_query(domain, qtype)
        else:
            domain, attack_type = attack
            print(f"[{i}/{len(attacks)}] {attack_type}: {domain}")
            dns_query(domain)
        time.sleep(0.5)
    
    print("\n[+] Ataques mixtos completados\n")

def main():
    """Función principal"""
    print("="*80)
    print("  SCRIPT DE PRUEBA DE ATAQUES DNS")
    print("  Simulación de ataques para probar dns_monitor.py")
    print("="*80)
    print(f"\n[*] Iniciando pruebas a las {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Dominio objetivo: {TARGET_DOMAIN}")
    print("\n[!] IMPORTANTE: Asegúrate de tener dns_monitor.py ejecutándose en otra terminal")
    print("[!] Presiona Ctrl+C para cancelar\n")
    
    time.sleep(3)  # Dar tiempo para leer el mensaje
    
    try:
        # Verificar que dig o host estén disponibles
        try:
            subprocess.run(['which', 'dig'], capture_output=True, check=True)
            print("[+] Herramienta 'dig' encontrada\n")
        except:
            try:
                subprocess.run(['which', 'host'], capture_output=True, check=True)
                print("[+] Herramienta 'host' encontrada\n")
            except:
                print("[!] ERROR: No se encontró 'dig' ni 'host'")
                print("[!] Instalar con: sudo apt-get install -y dnsutils")
                return
        
        # Ejecutar todas las pruebas
        test_normal_queries()
        time.sleep(2)
        
        test_subdomain_enumeration()
        time.sleep(2)
        
        test_dns_tunneling()
        time.sleep(2)
        
        test_dns_exfiltration()
        time.sleep(2)
        
        test_dns_amplification()
        time.sleep(2)
        
        test_mixed_attacks()
        time.sleep(2)
        
        # Opcional: descomentar para prueba masiva
        # test_massive_queries()
        
        print_section("PRUEBAS COMPLETADAS")
        print("[+] Todas las pruebas se han ejecutado")
        print(f"[+] Revisa el archivo dns_events_log.txt para ver los resultados")
        print(f"[+] Finalizado a las {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Pruebas interrumpidas por el usuario")
    except Exception as e:
        print(f"\n[!] Error durante las pruebas: {e}")

if __name__ == "__main__":
    main()

