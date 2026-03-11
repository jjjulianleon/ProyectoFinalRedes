#!/usr/bin/env python3
"""
Victim 2 - File server con flag en archivo accesible
La flag esta en un archivo dentro de /files/. El servidor lista
los archivos disponibles. El Red Team debe descubrir el archivo
correcto y descargar su contenido (interceptando trafico via MITM).
"""

import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

FLAG = os.environ.get("FLAG", "FLAG{default_flag_2}")
PORT = 80


class FileServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/files", **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            # Pagina con listado de archivos
            html = """<!DOCTYPE html>
<html>
<head><title>Victim 2 - File Server</title></head>
<body>
    <h1>Servidor de Archivos Internos</h1>
    <p>Documentos disponibles:</p>
    <ul>
        <li><a href="/reports/quarterly_report.txt">Reporte Trimestral</a></li>
        <li><a href="/reports/employee_list.txt">Lista de Empleados</a></li>
        <li><a href="/backup/db_credentials.txt">Backup Credenciales DB</a></li>
    </ul>
    <footer>File Server v2.1</footer>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            super().do_GET()

    def log_message(self, format, *args):
        print(f"[Victim2-FileServer] {self.client_address[0]} - {format % args}")


def setup_files():
    """Crea los archivos del file server, incluyendo uno con la flag"""
    os.makedirs("/files/reports", exist_ok=True)
    os.makedirs("/files/backup", exist_ok=True)

    with open("/files/reports/quarterly_report.txt", "w") as f:
        f.write("Q1 2026 Report\nRevenue: $1.2M\nExpenses: $800K\nProfit: $400K\n")

    with open("/files/reports/employee_list.txt", "w") as f:
        f.write("ID,Name,Department\n001,John Smith,IT\n002,Jane Doe,HR\n")

    # La flag esta en el archivo de credenciales de backup
    with open("/files/backup/db_credentials.txt", "w") as f:
        f.write(f"Database Credentials Backup\n")
        f.write(f"Host: db.internal.corp\n")
        f.write(f"User: admin\n")
        f.write(f"Password: {FLAG}\n")
        f.write(f"Database: production\n")


if __name__ == "__main__":
    setup_files()
    server = HTTPServer(("0.0.0.0", PORT), FileServerHandler)
    print(f"[Victim2] File Server en puerto {PORT}")
    print(f"[Victim2] Flag oculta en /backup/db_credentials.txt")
    server.serve_forever()
