"""Modo seguro: detecta comandos que pueden reiniciar, apagar o romper un servidor.

Las expresiones regulares están escritas para funcionar igual en Python y en JavaScript,
porque la terminal web las usa en el navegador. Es una red de seguridad contra errores,
no una barrera contra alguien que quiera saltársela.
"""
import re

from . import db

RULES = [
    (r"\b(reboot|poweroff|halt|shutdown)\b", "Reinicia o apaga el servidor"),
    (r"\b(tel)?init\s+[0156]\b", "Cambia el nivel de ejecución (apagar/reiniciar)"),
    (r"\bsystemctl\s+(\S+\s+)*(reboot|poweroff|halt|kexec|suspend|hibernate|rescue|emergency|isolate)\b",
     "Reinicia, apaga o cambia el modo del servidor"),
    (r"\b(systemctl|service)\b(?=.*\b(stop|disable|mask|restart|kill)\b)"
     r"(?=.*\b(sshd?|network|networking|NetworkManager|systemd-networkd|firewalld|nftables)\b)",
     "Puede cortar el acceso SSH o la red"),
    (r"\brm\s+(\S+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(\S+\s+)*"
     r"(/|/\*|/(etc|usr|var|boot|bin|sbin|lib|lib64|root|home|opt|srv)/?\*?)(\s|$)",
     "Borrado recursivo de directorios del sistema"),
    (r"\b(mkfs(\.\w+)?|mkswap|wipefs|fdisk|sfdisk|gdisk|parted|pvremove|vgremove|lvremove)\b",
     "Formatea o modifica discos y particiones"),
    (r"\bdd\b.*\bof=/dev/|>\s*/dev/(sd|hd|vd|xvd|nvme|mapper)|\bshred\b.*/dev/",
     "Escribe directamente sobre un disco"),
    (r"\bkill\s+(-\S+\s+)*1(\s|$)|\b(pkill|killall)\s+(-\S+\s+)*(systemd|init|sshd)\b",
     "Mata procesos críticos del sistema"),
    (r"\b(userdel|deluser|groupdel)\b|\bpasswd\s+(\S+\s+)*(-l|-d|--lock|--delete)\b|\busermod\s+.*(-L|--lock)\b",
     "Borra o bloquea usuarios"),
    (r"\b(chmod|chown|chgrp)\s+(\S+\s+)*-[a-zA-Z]*R[a-zA-Z]*\s+(\S+\s+)?/(\s|$|etc|usr|var|bin|lib|boot)",
     "Cambia permisos o propietarios de todo el sistema"),
    (r"\biptables\s+(\S+\s+)*(-F|--flush)\b|\biptables\s+.*-P\s+\S+\s+DROP\b|\bnft\s+flush\b|\bufw\s+(disable|reset)\b",
     "Cambia el cortafuegos (puede cortar el acceso)"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "Bomba fork (bloquea el servidor)"),
    (r"/proc/sysrq-trigger", "Fuerza un reinicio o caída del kernel"),
    (r"\bcrontab\s+(\S+\s+)*-r\b", "Borra todas las tareas programadas"),
    (r"\b(yum|dnf|apt|apt-get|zypper)\s+(\S+\s+)*(remove|erase|purge|autoremove|install|update|upgrade|"
     r"dist-upgrade|full-upgrade|reinstall|downgrade)\b|\brpm\s+(\S+\s+)*-e\b|\bdpkg\s+(\S+\s+)*(-r|-P|-i|--remove|--purge)\b"
     r"|\bsnap\s+(remove|install|refresh)\b",
     "Instala, actualiza o desinstala paquetes"),
    (r"\b(sed|perl)\s+(\S+\s+)*-i\b.*/etc/(passwd|shadow|group|sudoers|fstab|ssh/sshd_config)"
     r"|>\s*/etc/(passwd|shadow|group|sudoers|fstab|hosts)\b",
     "Modifica ficheros críticos del sistema"),
    # Docker / Podman: las palabras se buscan en la misma orden (sin cruzar |, ; ni &)
    (r"\b(docker|podman)(-compose)?\s+(?:[^\s|;&]+\s+)*(stop|kill|rm|rmi|down|prune)(\s|$)",
     "Para o borra contenedores, imágenes o volúmenes Docker/Podman"),
    (r"\b(systemctl|service)\b(?=.*\b(stop|restart|disable|mask|kill)\b)(?=.*\b(docker|podman|containerd)\b)",
     "Para o reinicia el servicio Docker/Podman (afecta a todos sus contenedores)"),
]
_COMPILED = [(re.compile(p, re.I), d) for p, d in RULES]
CONFIRM_WORD = "CONFIRMO"


def enabled():
    return db.get_setting("safe_mode", "1") == "1"


def check(command):
    """Devuelve la lista de motivos por los que el comando es peligroso (vacía si no lo es)."""
    return [desc for rx, desc in _COMPILED if rx.search(command or "")]


def js_rules():
    return [{"re": p, "desc": d} for p, d in RULES]
