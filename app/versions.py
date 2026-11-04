"""Package version comparison in the style of dpkg (Debian/Ubuntu) and rpm (RHEL)."""

DIGITS = "0123456789"
LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------- dpkg ----------

def _dpkg_order(c):
    if c in DIGITS:
        return 0
    if c in LETTERS:
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _dpkg_verrevcmp(a, b):
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in DIGITS) or (j < lb and b[j] not in DIGITS):
            ac = _dpkg_order(a[i] if i < la else "")
            bc = _dpkg_order(b[j] if j < lb else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i] in DIGITS and j < lb and b[j] in DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in DIGITS:
            return 1
        if j < lb and b[j] in DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_evr(v, dpkg):
    epoch = None
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel


def dpkg_compare(a, b, ignore_epoch=False):
    ea, va, ra = _split_evr(a, True)
    eb, vb, rb = _split_evr(b, True)
    if not ignore_epoch and (ea or 0) != (eb or 0):
        return (ea or 0) - (eb or 0)
    r = _dpkg_verrevcmp(va, vb)
    if r:
        return r
    return _dpkg_verrevcmp(ra, rb)


# ---------- rpm ----------

def _isalnum(c):
    return c in DIGITS or c in LETTERS


def rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        s1, s2 = i, j
        if a[i] in DIGITS:
            while i < la and a[i] in DIGITS:
                i += 1
            while j < lb and b[j] in DIGITS:
                j += 1
            isnum = True
        else:
            while i < la and a[i] in LETTERS:
                i += 1
            while j < lb and b[j] in LETTERS:
                j += 1
            isnum = False
        seg1, seg2 = a[s1:i], b[s2:j]
        if not seg2:
            return 1 if isnum else -1
        if isnum:
            seg1, seg2 = seg1.lstrip("0"), seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def rpm_compare(a, b, ignore_epoch=False):
    ea, va, ra = _split_evr(a, False)
    eb, vb, rb = _split_evr(b, False)
    if not ignore_epoch and (ea or 0) != (eb or 0):
        return 1 if (ea or 0) > (eb or 0) else -1
    r = rpmvercmp(va, vb)
    if r or not ra or not rb:
        return r
    return rpmvercmp(ra, rb)


# ---------- common API ----------

def compare(installed, target, family):
    """Compares the installed version with the one given by the user.

    If the user does not write an epoch ("1:"), the epoch of the installed package is ignored:
    so "openssl < 3.0.7-28.el9" works even if on RHEL the package is "1:3.0.7-27.el9".
    """
    ignore_epoch = ":" not in target
    if family == "rpm":
        return rpm_compare(installed, target, ignore_epoch)
    return dpkg_compare(installed, target, ignore_epoch)


OPERATORS = {
    "<": lambda r: r < 0,
    "<=": lambda r: r <= 0,
    "=": lambda r: r == 0,
    ">=": lambda r: r >= 0,
    ">": lambda r: r > 0,
}


def matches(installed, op, target, family):
    if not op or not target:
        return True
    try:
        return OPERATORS[op](compare(installed, target, family))
    except Exception:
        return False
