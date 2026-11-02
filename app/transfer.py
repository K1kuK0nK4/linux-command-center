"""Lectura y escritura de ficheros de inventario (Excel .xlsx y CSV)."""
import csv
import io

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# (columna, obligatoria, descripción, ejemplo)
COLUMNS = [
    ("nombre", True, "Nombre con el que verás el servidor.", "web01-pro"),
    ("host", True, "IP o hostname para conectar por SSH.", "10.20.30.40"),
    ("puerto", False, "Puerto SSH. Vacío = 22.", "22"),
    ("cliente", False, "Cliente o empresa a la que pertenece.", "ClienteA"),
    ("entorno", False, "PRO, PRE, DEV…", "PRO"),
    ("etiquetas", False, "Separadas por comas. Se crean solas si no existen.", "web, dmz"),
    ("usuario", False, "Usuario SSH propio de este servidor.", "analista"),
    ("password", False, "Contraseña SSH de ese usuario.", "********"),
    ("sudo_password", False, "Contraseña de sudo, solo si es distinta de la de SSH.", ""),
    ("credencial", False, "En vez de usuario/password: nombre de una credencial compartida que ya exista.", ""),
    ("notas", False, "Texto libre.", ""),
]
HEADERS = [c[0] for c in COLUMNS]
ALIASES = {"ip": "host", "hostname": "host", "port": "puerto", "user": "usuario", "username": "usuario",
           "contraseña": "password", "contrasena": "password", "clave": "password", "tags": "etiquetas",
           "etiqueta": "etiquetas", "name": "nombre", "client": "cliente", "environment": "entorno",
           "notes": "notas", "sudo": "sudo_password"}


FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value):
    """Evita la inyección de fórmulas en CSV: Excel ejecutaría '=...' como una fórmula."""
    if isinstance(value, str) and value.startswith(FORMULA_CHARS):
        return "'" + value
    return value


def _unsafe_cell(value):
    # Deshace safe_cell al importar un fichero exportado por la propia aplicación
    if value.startswith("'") and value[1:2] in ("=", "+", "-", "@"):
        return value[1:]
    return value


def _norm_header(h):
    h = str(h or "").strip().lower().replace(" ", "_").rstrip("*")
    return ALIASES.get(h, h)


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return _unsafe_cell(str(v).strip())


def read_rows(filename, raw):
    """Devuelve una lista de (nº de fila, dict columna→valor) del fichero subido."""
    if filename.lower().endswith((".xlsx", ".xlsm")):
        ws = load_workbook(io.BytesIO(raw), read_only=True, data_only=True).worksheets[0]
        rows = list(ws.iter_rows(values_only=True))
    else:
        for enc in ("utf-8-sig", "cp1252"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        first = text.split("\n", 1)[0]
        rows = list(csv.reader(io.StringIO(text), delimiter=";" if first.count(";") >= first.count(",") else ","))
    if not rows:
        return []
    header = [_norm_header(h) for h in rows[0]]
    out = []
    for n, row in enumerate(rows[1:], start=2):
        values = {h: _cell(v) for h, v in zip(header, row) if h}
        if any(values.values()):
            out.append((n, values))
    return out


def write_csv(rows):
    buf = io.StringIO()
    buf.write("﻿")
    w = csv.writer(buf, delimiter=";")
    w.writerow(HEADERS)
    w.writerows([[safe_cell(r.get(h, "")) for h in HEADERS] for r in rows])
    return buf.getvalue().encode("utf-8")


def write_xlsx(rows, with_passwords):
    wb = Workbook()
    ws = wb.active
    ws.title = "Servidores"
    ws.append(HEADERS)
    for r in rows:
        ws.append([r.get(h, "") for h in HEADERS])
        # openpyxl guardaría '=...' como fórmula: se fuerza a texto
        for cell in ws[ws.max_row]:
            if cell.data_type == "f":
                cell.data_type = "s"
    req_fill = PatternFill("solid", fgColor="2A78D6")
    opt_fill = PatternFill("solid", fgColor="52514E")
    for i, (_, required, _, _) in enumerate(COLUMNS, start=1):
        c = ws.cell(row=1, column=i)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = req_fill if required else opt_fill
        ws.column_dimensions[get_column_letter(i)].width = 22 if HEADERS[i - 1] != "notas" else 40
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    help_ws = wb.create_sheet("Instrucciones")
    help_ws.append(["Columna", "¿Obligatoria?", "Qué poner", "Ejemplo"])
    for name, required, desc, example in COLUMNS:
        help_ws.append([name, "SÍ" if required else "no", desc, example])
    help_ws.append([])
    help_ws.append(["Notas"])
    for line in (
        "Rellena una fila por servidor en la hoja 'servidores'. Solo 'nombre' y 'host' son obligatorias.",
        "Para la credencial usa UNA opción: 'usuario' + 'password' (propia del servidor) o 'credencial' (compartida).",
        "Al importar, un servidor que ya existe (mismo cliente, host y puerto) se puede actualizar; "
        "las celdas vacías no cambian nada. La misma IP en clientes distintos son servidores distintas.",
        "Las claves SSH (.pem) no se exportan: se configuran en Credenciales.",
        "AVISO: este fichero contiene contraseñas en claro: bórralo cuando termines." if with_passwords else
        "Este fichero NO contiene contraseñas.",
    ):
        help_ws.append([line])
    for cell in help_ws[1]:
        cell.font = Font(bold=True)
    for col, width in zip("ABCD", (16, 14, 80, 20)):
        help_ws.column_dimensions[col].width = width
    for row in help_ws.iter_rows():
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
