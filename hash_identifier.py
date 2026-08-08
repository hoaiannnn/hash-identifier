import string
from dataclasses import dataclass

# global variables
HEX_CHARACTERS = "0123456789abcdefABCDEF"
DESCRYPT_CHARACTERS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
@dataclass(frozen=True)
class HashCandidate:
    algorithm: str
    confidence: str
    reason: str

PREFIX_RULES: dict[str, tuple[str, str]] = {
    # Argon2
    "$argon2d$": ("Argon2d", "high"),
    "$argon2i$": ("Argon2i", "high"),
    "$argon2id$": ("Argon2id", "high"),

    # bcrypt
    "$2$": ("bcrypt (original)", "high"),
    "$2a$": ("bcrypt", "high"),
    "$2b$": ("bcrypt", "high"),
    "$2y$": ("bcrypt", "high"),
    "$2x$": ("bcrypt", "high"),

    # PBKDF2
    "pbkdf2_sha256$": ("PBKDF2-HMAC-SHA256 (Django)", "high"),
    "pbkdf2_sha1$": ("PBKDF2-HMAC-SHA1 (Django)", "high"),
    "argon2$": ("Argon2 (Django)", "high"),
    "bcrypt_sha256$": ("bcrypt-SHA256 (Django)", "high"),
    "bcrypt$": ("bcrypt (Django)", "high"),
    "scrypt$": ("scrypt (Django)", "high"),

    # Unix crypt(3) family
    "$6$": ("SHA-512 crypt", "high"),
    "$5$": ("SHA-256 crypt", "high"),
    "$1$": ("MD5 crypt", "high"),
    "$apr1$": ("Apache MD5 (APR1)", "high"),

    # phpass
    "$P$": ("phpass Portable", "high"),
    "$H$": ("phpass (phpBB)", "high"),
    
    # Hash Function
    "{MD5}": ("LDAP MD5", "high"),
    "{SMD5}": ("LDAP SMD5", "high"),
    "{SHA}": ("LDAP SHA", "high"),
    "{SSHA}": ("LDAP SSHA", "high")
}

def _is_hex(s: str) -> bool:
    if len(s) <= 0:
        return False
    return all(c in HEX_CHARACTERS for c in s)

def _is_mysql5(s: str) -> bool:
    if len(s[1:]) == 40 and s.startswith("*") and _is_hex(s[1:]):
        return True
    return False

def _is_descrypt(s: str) -> bool:
    if len(s) == 13 and all(c in DESCRYPT_CHARACTERS for c in s):
        return True
    return False

HEX_LENGTH_RULES: dict[int, list[str]] = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1"],
    64: ["SHA-256"],
    128: ["SHA-512"],
}