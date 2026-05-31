import mysql.connector
import os
from contextlib import contextmanager
from datetime import datetime
from tools.scanner import scan_active_hosts


# --- Conexión como context manager ---
# Evita que una excepción deje conexiones abiertas

@contextmanager
def get_db_connection():
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST", "netguard_mysql"),
        port=int(os.getenv("DB_PORT", 3306)),
        database=os.getenv("DB_DATABASE", "netguard"),
        user=os.getenv("DB_USERNAME", "netguard"),
        password=os.getenv("DB_PASSWORD", "changeme")
    )
    try:
        yield conn
    finally:
        conn.close()


def check_new_devices(network: str) -> dict:
    """
    Escanea la red y detecta dispositivos nuevos comparando con la BD.
    """
    try:
        scan_result = scan_active_hosts(network)

        if "error" in scan_result:
            return scan_result

        current_hosts = scan_result.get("hosts", [])
        new_devices   = []
        known_devices = []
        now           = datetime.now()

        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            for host in current_hosts:
                ip       = host["ip"]
                hostname = host.get("hostname", "") or ""

                cursor.execute("SELECT id FROM devices WHERE ip = %s", (ip,))
                existing = cursor.fetchone()

                if existing:
                    cursor.execute(
                        "UPDATE devices SET last_seen = %s, hostname = %s, is_new = 0 WHERE ip = %s",
                        (now, hostname, ip)
                    )
                    known_devices.append(ip)
                else:
                    cursor.execute(
                        """INSERT INTO devices
                               (ip, hostname, state, is_new, first_seen, last_seen, created_at, updated_at)
                           VALUES (%s, %s, 'up', 1, %s, %s, %s, %s)""",
                        (ip, hostname, now, now, now, now)
                    )
                    new_devices.append({"ip": ip, "hostname": hostname})

            # Marcar como offline los hosts que ya no responden
            if current_hosts:
                active_ips    = [h["ip"] for h in current_hosts]
                placeholders  = ", ".join(["%s"] * len(active_ips))
                cursor.execute(
                    f"UPDATE devices SET state = 'down', last_seen = %s "
                    f"WHERE ip NOT IN ({placeholders}) AND state = 'up'",
                    [now, *active_ips]
                )

            conn.commit()
            cursor.close()

        return {
            "network":         network,
            "total_scanned":   len(current_hosts),
            "new_devices":     new_devices,
            "known_devices":   len(known_devices),
            "has_new_devices": len(new_devices) > 0,
        }

    except mysql.connector.Error as e:
        return {"error": f"Error de base de datos: {e}"}
    except Exception as e:
        return {"error": str(e)}


def get_all_devices() -> dict:
    """
    Retorna todos los dispositivos registrados en la BD con su estado actual.
    Útil para el dashboard y para que el agente responda preguntas como
    '¿qué dispositivos conozco?' o '¿cuáles están offline?'
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """SELECT ip, hostname, state, is_new,
                          first_seen, last_seen
                   FROM devices
                   ORDER BY last_seen DESC"""
            )
            devices = cursor.fetchall()

            # Serializar datetimes para que sean JSON-safe
            for d in devices:
                for key in ("first_seen", "last_seen"):
                    if isinstance(d[key], datetime):
                        d[key] = d[key].isoformat()

            cursor.close()

        online  = [d for d in devices if d["state"] == "up"]
        offline = [d for d in devices if d["state"] == "down"]

        return {
            "total":   len(devices),
            "online":  len(online),
            "offline": len(offline),
            "devices": devices,
        }

    except mysql.connector.Error as e:
        return {"error": f"Error de base de datos: {e}"}
    except Exception as e:
        return {"error": str(e)}