"""Reading and writing inventory files (Excel .xlsx and CSV)."""
import csv
import io

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

# (file header, internal key, required, description, example).
# Headers are always in English, whatever the application language.
COLUMNS = [
    ("name", "nombre", True, "Name you will see for the server.", "web01-pro"),
    ("host", "host", True, "IP or hostname to connect via SSH.", "10.20.30.40"),
    ("port", "puerto", False, "SSH port. Empty = 22.", "22"),
    ("organization", "cliente", False, "Organization (client, company, department…) it belongs to.", "Acme"),
    ("environment", "entorno", False, "PRO, PRE, DEV…", "PRO"),
    ("tags", "etiquetas", False, "Comma separated. Created automatically if they don't exist.", "web, dmz"),
    ("user", "usuario", False, "SSH user specific to this server.", "analista"),
    ("password", "password", False, "SSH password of that user.", "********"),
    ("sudo_password", "sudo_password", False, "sudo password, only if different from the SSH one.", ""),
    ("credential", "credential", False, "Instead of user/password: name of an existing shared credential.", ""),
    ("notes", "notas", False, "Free text.", ""),
]
HEADERS = [c[0] for c in COLUMNS]
KEYS = [c[1] for c in COLUMNS]
# Headers accepted on import: the English ones, the old Spanish ones and some common variants
ALIASES = {**{c[0]: c[1] for c in COLUMNS}, **{c[1]: c[1] for c in COLUMNS},
           "ip": "host", "hostname": "host", "username": "usuario", "contraseña": "password", "contrasena": "password",
           "credencial": "credential", "client": "cliente",
           "clave": "password", "etiqueta": "etiquetas", "sudo": "sudo_password"}


FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value):
    """Prevents formula injection in CSV: Excel would run '=...' as a formula."""
    if isinstance(value, str) and value.startswith(FORMULA_CHARS):
        return "'" + value
    return value


def _unsafe_cell(value):
    # Undoes safe_cell when importing a file exported by this application
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
    """Returns a list of (row number, dict column→value) from the uploaded file."""
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
    w.writerows([[safe_cell(r.get(k, "")) for k in KEYS] for r in rows])
    return buf.getvalue().encode("utf-8")


def write_xlsx(rows, with_passwords):
    wb = Workbook()
    ws = wb.active
    ws.title = "Servers"
    ws.append(HEADERS)
    for r in rows:
        ws.append([r.get(k, "") for k in KEYS])
        # openpyxl would save '=...' as a formula: it is forced to text
        for cell in ws[ws.max_row]:
            if cell.data_type == "f":
                cell.data_type = "s"
    req_fill = PatternFill("solid", fgColor="2A78D6")
    opt_fill = PatternFill("solid", fgColor="52514E")
    for i, (header, _, required, _, _) in enumerate(COLUMNS, start=1):
        c = ws.cell(row=1, column=i)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = req_fill if required else opt_fill   # blue = required
        ws.column_dimensions[get_column_letter(i)].width = 40 if header == "notes" else 22
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
