
"""Demo authentication for CampusBridge Student Support Agent."""
from __future__ import annotations
import hashlib
import hmac
from dataclasses import dataclass

_DEMO = {
    # Customized student accounts
    "anaya": ("STU1001", "student"),
    "rohan": ("STU1002", "student"),
    "kiara": ("STU1003", "student"),

    # Backward compatibility for existing tests
    "asha": ("STU1001", "student"),
    "kabir": ("STU1002", "student"),
    "mira": ("STU1003", "student"),

    # Approver account
    "approver": (None, "approver"),
}

_PASSWORDS = {
    "anaya": "Anaya-Demo-2026!",
    "rohan": "Rohan-Demo-2026!",
    "kiara": "Kiara-Demo-2026!",
    "asha": "Asha-Demo-2026!",
    "kabir": "Kabir-Demo-2026!",
    "mira": "Mira-Demo-2026!",
    "approver": "Approve-Demo-2026!",
}

_SALT = b"student-support-assignment-demo"

_HASHES = {
    u: hashlib.pbkdf2_hmac("sha256", p.encode(), _SALT, 200_000)
    for u, p in _PASSWORDS.items()
}

@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    student_id: str | None

def authenticate(username: str, password: str) -> Principal | None:
    username = username.strip().lower()
    record = _DEMO.get(username)

    if not record:
        return None

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), _SALT, 200_000
    )

    if not hmac.compare_digest(candidate, _HASHES[username]):
        return None

    return Principal(username, record[1], record[0])
