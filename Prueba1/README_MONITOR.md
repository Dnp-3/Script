# Monitor de Seguridad Web - milnomes.es

Scripts de monitoreo de seguridad para detectar ataques y vulnerabilidades en la web alojada en `10.104.0.19` (milnomes.es y nadieentiendemiletra.milnomes.es).

## Archivos

- **web_monitor.py**: Script básico de monitoreo en tiempo real
- **web_monitor_advanced.py**: Script avanzado con análisis profundo de vulnerabilidades (RECOMENDADO)
- **web_monitor_kali.sh**: Script bash para monitoreo rápido con tcpdump
- **analyze_web_logs.py**: Analizador de logs de servidor web (Apache/Nginx)

## Instalación

```bash
# Instalar dependencias
sudo apt-get update
sudo apt-get install -y tcpdump python3

# Dar permisos de ejecución
chmod +x web_monitor.py web_monitor_advanced.py
```

## Uso

Primero, navega a la carpeta:
```bash
cd /home/lamp/web_security_monitor
```

### Script Básico (Monitoreo en Tiempo Real)
```bash
sudo python3 web_monitor.py
```

### Script Avanzado (Recomendado)
Monitoreo en tiempo real con análisis profundo de vulnerabilidades:
```bash
sudo python3 web_monitor_advanced.py
```

### Script Bash (Monitoreo Rápido)
Monitoreo básico usando solo tcpdump:
```bash
sudo ./web_monitor_kali.sh
```

### Analizador de Logs de Servidor
Si tienes acceso a los logs del servidor web (Apache/Nginx):
```bash
sudo python3 analyze_web_logs.py
```

**Nota**: Este script busca logs en ubicaciones comunes:
- `/var/log/apache2/access.log`
- `/var/log/apache2/error.log`
- `/var/log/nginx/access.log`
- `/var/log/nginx/error.log`

## Características

### Detección de Ataques
- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection
- File Upload malicioso
- LFI/RFI
- SSRF
- XXE
- Authentication Bypass
- CSRF
- IDOR
- Open Redirect
- SSTI

### Análisis de Vulnerabilidades
- Paneles de administración expuestos
- Archivos sensibles (.git, .env, etc.)
- Endpoints de API
- Archivos de backup

### Funcionalidades

#### Monitoreo en Tiempo Real (web_monitor.py / web_monitor_advanced.py)
- Captura de tráfico HTTP/HTTPS en tiempo real usando tcpdump
- Registro inmediato de eventos sospechosos
- Guardado automático cada 5 minutos con estadísticas completas
- Análisis de patrones de vulnerabilidades
- Detección automática de interfaz de red
- Análisis de headers HTTP (User-Agent, Referer, Cookies)
- Detección de datos POST maliciosos

#### Análisis de Logs (analyze_web_logs.py)
- Análisis de logs históricos de Apache/Nginx
- Búsqueda de patrones de ataque en logs
- Estadísticas de ataques por tipo
- Identificación de IPs atacantes
- Análisis de códigos de estado HTTP

## Archivo de Log

Los eventos se guardan en: `web_attacks_log.txt` (en la misma carpeta del script)

### Formato del Log

El archivo contiene:
- **Estadísticas de ataques**: Resumen de tipos de ataques detectados con porcentajes
- **Análisis de vulnerabilidades**: Intentos de acceso a recursos sensibles
- **Eventos críticos**: Eventos con ataques detectados (últimos 50-100)
- **Todos los eventos**: Registro completo de actividad (últimos 200)

### Actualización

El archivo se actualiza:
- **Inmediatamente**: Cada evento sospechoso se escribe al instante
- **Cada 5 minutos**: Se reescribe completamente con estadísticas actualizadas
- **Al detener**: Se guarda un resumen final al presionar Ctrl+C

## Notas Importantes

- **Permisos**: Requiere permisos de root (sudo) para capturar paquetes de red
- **Interfaz de red**: Se detecta automáticamente, pero puedes modificarla en el script
- **Detención**: Presiona Ctrl+C para detener el monitoreo de forma segura
- **Persistencia**: Los logs se mantienen entre ejecuciones (se reescriben cada 5 min)
- **Rendimiento**: El script está optimizado para no sobrecargar el sistema
- **Puertos monitoreados**: 80, 443, 8080, 8443 (HTTP/HTTPS)

## Ejemplo de Salida

```
[+] 2024-01-15 14:30:25 - GET /admin/login.php | Ataques: 1 | Vulns: 1
[+] 2024-01-15 14:30:30 - POST /api/user?id=1' OR '1'='1 | Ataques: 1 | Vulns: 0
[+] Log completo guardado: 150 eventos, 25 ataques
```

## Troubleshooting

### Error: "tcpdump: no se puede abrir la interfaz"
- Verifica que la interfaz de red existe: `ip link show`
- Modifica la variable `INTERFACE` en el script

### Error: "Permission denied"
- Asegúrate de ejecutar con `sudo`
- Verifica permisos de lectura en logs si usas `analyze_web_logs.py`

### No se detectan eventos
- Verifica que el tráfico esté pasando por la interfaz monitoreada
- Comprueba que la IP objetivo sea correcta
- Asegúrate de que los dominios coincidan con los configurados

## Personalización

Puedes modificar las siguientes variables en los scripts:

```python
TARGET_IP = "10.104.0.19"  # IP objetivo
TARGET_DOMAINS = ["milnomes.es", "nadieentiendemiletra.milnomes.es"]  # Dominios
LOG_FILE = "web_attacks_log.txt"  # Archivo de log (relativo al script)
UPDATE_INTERVAL = 300  # Intervalo de guardado (segundos)
```

## Estructura de Carpetas

```
web_security_monitor/
├── web_monitor.py              # Script básico
├── web_monitor_advanced.py     # Script avanzado (recomendado)
├── web_monitor_kali.sh         # Script bash
├── analyze_web_logs.py         # Analizador de logs
├── README_MONITOR.md           # Esta documentación
└── web_attacks_log.txt         # Archivo de log (se crea al ejecutar)
```

