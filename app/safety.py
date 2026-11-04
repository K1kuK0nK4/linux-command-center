"""Safe mode: detects commands that may reboot, shut down or break a server.

The regular expressions are written to work the same in Python and in JavaScript,
because the web terminal uses them in the browser. It is a safety net against mistakes,
not a barrier against someone who wants to bypass it.
"""
import re

from . import db

RULES = [
    (r"\b(reboot|poweroff|halt|shutdown)\b", "Reboots or shuts down the server"),
    (r"\b(tel)?init\s+[0156]\b", "Changes the runlevel (shutdown/reboot)"),
    (r"\bsystemctl\s+(\S+\s+)*(reboot|poweroff|halt|kexec|suspend|hibernate|rescue|emergency|isolate)\b",
     "Reboots, shuts down or changes the server's mode"),
    (r"\b(systemctl|service)\b(?=.*\b(stop|disable|mask|restart|kill)\b)"
     r"(?=.*\b(sshd?|network|networking|NetworkManager|systemd-networkd|firewalld|nftables)\b)",
     "May cut SSH access or the network"),
    (r"\brm\s+(\S+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(\S+\s+)*"
     r"(/|/\*|/(etc|usr|var|boot|bin|sbin|lib|lib64|root|home|opt|srv)/?\*?)(\s|$)",
     "Recursive deletion of system directories"),
    (r"\b(mkfs(\.\w+)?|mkswap|wipefs|fdisk|sfdisk|gdisk|parted|pvremove|vgremove|lvremove)\b",
     "Formats or modifies disks and partitions"),
    (r"\bdd\b.*\bof=/dev/|>\s*/dev/(sd|hd|vd|xvd|nvme|mapper)|\bshred\b.*/dev/",
     "Writes directly to a disk"),
    (r"\bkill\s+(-\S+\s+)*1(\s|$)|\b(pkill|killall)\s+(-\S+\s+)*(systemd|init|sshd)\b",
     "Kills critical system processes"),
    (r"\b(userdel|deluser|groupdel)\b|\bpasswd\s+(\S+\s+)*(-l|-d|--lock|--delete)\b|\busermod\s+.*(-L|--lock)\b",
     "Deletes or locks users"),
    (r"\b(chmod|chown|chgrp)\s+(\S+\s+)*-[a-zA-Z]*R[a-zA-Z]*\s+(\S+\s+)?/(\s|$|etc|usr|var|bin|lib|boot)",
     "Changes permissions or owners of the whole system"),
    (r"\biptables\s+(\S+\s+)*(-F|--flush)\b|\biptables\s+.*-P\s+\S+\s+DROP\b|\bnft\s+flush\b|\bufw\s+(disable|reset)\b",
     "Changes the firewall (may cut access)"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "Fork bomb (hangs the server)"),
    (r"/proc/sysrq-trigger", "Forces a kernel reboot or crash"),
    (r"\bcrontab\s+(\S+\s+)*-r\b", "Deletes all scheduled tasks"),
    (r"\b(yum|dnf|apt|apt-get|zypper)\s+(\S+\s+)*(remove|erase|purge|autoremove|install|update|upgrade|"
     r"dist-upgrade|full-upgrade|reinstall|downgrade)\b|\brpm\s+(\S+\s+)*-e\b|\bdpkg\s+(\S+\s+)*(-r|-P|-i|--remove|--purge)\b"
     r"|\bsnap\s+(remove|install|refresh)\b",
     "Installs, updates or removes packages"),
    (r"\b(sed|perl)\s+(\S+\s+)*-i\b.*/etc/(passwd|shadow|group|sudoers|fstab|ssh/sshd_config)"
     r"|>\s*/etc/(passwd|shadow|group|sudoers|fstab|hosts)\b",
     "Modifies critical system files"),
    # Docker / Podman: the words are matched in the same order (without crossing |, ; or &)
    (r"\b(docker|podman)(-compose)?\s+(?:[^\s|;&]+\s+)*(stop|kill|rm|rmi|down|prune)(\s|$)",
     "Stops or removes Docker/Podman containers, images or volumes"),
    (r"\b(systemctl|service)\b(?=.*\b(stop|restart|disable|mask|kill)\b)(?=.*\b(docker|podman|containerd)\b)",
     "Stops or restarts the Docker/Podman service (affects all its containers)"),
]
_COMPILED = [(re.compile(p, re.I), d) for p, d in RULES]
CONFIRM_WORD = "CONFIRM"  # the same in every language (also in static/danger.js)


def enabled():
    return db.get_setting("safe_mode", "1") == "1"


def check(command):
    """Returns the list of reasons why the command is dangerous (empty if it is not)."""
    return [desc for rx, desc in _COMPILED if rx.search(command or "")]


def js_rules():
    return [{"re": p, "desc": d} for p, d in RULES]
