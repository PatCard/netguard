import mysql.connector
import os
from datetime import datetime
from tools.scanner import scan_active_hosts

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "netguard_mysql"),
        port=int(os.getenv("DB_PORT", 3306)),
        database=os.getenv("DB_DATABASE", "netguard"),
        user=os.getenv("DB_USERNAME", "netguard"),
        password=os.getenv("DB_PASSWORD", "changeme")
    )

def check_new_devices(network: str) -> dict:
    """
    Escanea la red y detecta dispositivos nuevos comparando con la BD.
    """
    try:
        scan_result = scan_active_hosts(network)

        if "error" in scan_result:
            return scan_result

        current_hosts = scan_result.get("hosts", [])
        new_devices = []
        known_devices = []

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        for host in current_hosts:
            ip = host["ip"]
            hostname = host.get("hostname", "")
            now = datetime.now()

            # Verificar si el dispositivo ya existe
            cursor.execute("SELECT * FROM devices WHERE ip = %s", (ip,))
            existing = cursor.fetchone()

            if existing:
                # Actualizar last_seen
                cursor.execute(
                    "UPDATE devices SET last_seen = %s, is_new = 0 WHERE ip = %s",
                    (now, ip)
                )
                known_devices.append(ip)
            else:
                # Dispositivo nuevo
                cursor.execute(
                    """INSERT INTO devices (ip, hostname, state, is_new, first_seen, last_seen, created_at, updated_at)
                       VALUES (%s, %s, 'up', 1, %s, %s, %s, %s)""",
                    (ip, hostname, now, now, now, now)
                )
                new_devices.append({
                    "ip": ip,
                    "hostname": hostname
                })

        conn.commit()
        cursor.close()
        conn.close()

        return {
            "network": network,
            "total_scanned": len(current_hosts),
            "new_devices": new_devices,
            "known_devices": len(known_devices),
            "has_new_devices": len(new_devices) > 0
        }

    except Exception as e:
        return {"error": str(e)}
