#!/bin/bash
#
# Script de Monitoreo de Seguridad Web para Kali Linux
# Monitorea ataques hacia milnomes.es (10.104.0.19)
#

TARGET_IP="10.104.0.19"
TARGET_DOMAINS="milnomes.es nadieentiendemiletra.milnomes.es"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/web_attacks_log.txt"
INTERFACE=$(ip route get $TARGET_IP 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")

echo "=========================================="
echo "Monitor de Seguridad Web - Kali Linux"
echo "=========================================="
echo "IP Objetivo: $TARGET_IP"
echo "Dominios: $TARGET_DOMAINS"
echo "Interfaz: $INTERFACE"
echo "Log: $LOG_FILE"
echo "=========================================="
echo ""

# Verificar permisos
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Este script requiere permisos de root"
    echo "[*] Ejecutar con: sudo $0"
    exit 1
fi

# Verificar dependencias
echo "[*] Verificando dependencias..."
for cmd in tcpdump python3; do
    if ! command -v $cmd &> /dev/null; then
        echo "[!] $cmd no está instalado"
        echo "[*] Instalar con: sudo apt-get install -y $cmd"
        exit 1
    fi
done
echo "[+] Dependencias OK"
echo ""

# Función para limpiar al salir
cleanup() {
    echo ""
    echo "[*] Deteniendo monitoreo..."
    kill $TCPDUMP_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Iniciar captura de paquetes
echo "[*] Iniciando captura de paquetes..."
tcpdump -i $INTERFACE -A -s 0 -n "host $TARGET_IP and (port 80 or port 443 or port 8080)" 2>/dev/null | \
while IFS= read -r line; do
    # Detectar peticiones HTTP
    if echo "$line" | grep -qiE "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)"; then
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$TIMESTAMP] Petición detectada: $line" | tee -a "$LOG_FILE"
    fi
done &

TCPDUMP_PID=$!

echo "[+] Monitoreo activo (PID: $TCPDUMP_PID)"
echo "[*] Presiona Ctrl+C para detener"
echo ""

# Mantener el script corriendo
wait $TCPDUMP_PID

