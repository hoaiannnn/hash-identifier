import string
from dataclasses import dataclass
import argparse

# global variables
HEX_CHARACTERS = "0123456789abcdefABCDEF"
DESCRYPT_CHARACTERS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE64_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
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
    8: ["CRC32"],
    32: ["MD5", "NTLM", "MD4", "LM"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224"],
    64: ["SHA-256", "SM3", "GOST R 34.11-94"],
    96: ["SHA-384"],
    128: ["SHA-512", "Whirlpool"],
}

def identify(text: str) -> list[HashCandidate]:
    for prefix, (algorithm, confidence) in PREFIX_RULES.items():
        if text.startswith(prefix):
            candidate = HashCandidate(algorithm, confidence, f"matched prefix '{prefix}'")
            return [candidate]
        
    if _is_mysql5(text):
        candidate = HashCandidate("MySQL4.1/MySQL5", "high", "matched MySQL 4.1/MySQL5 hash format")
        return [candidate]
    
    if _is_descrypt(text):
        candidate = HashCandidate("DES crypt", "medium", "matched DES crypt hash format")
        return [candidate]

    if _is_hex(text) and len(text) in HEX_LENGTH_RULES.keys():
        x = HEX_LENGTH_RULES[len(text)]
        list_candidate = []

        check = 0
        for c in x:
            if check == 0:
                check = 1
                candidate = HashCandidate(c, "medium", f"{len(text)} hex chars, most common")
                list_candidate.append(candidate)
            else:
                candidate = HashCandidate(c, "low", f"{len(text)} hex chars, less common")
                list_candidate.append(candidate)

        return list_candidate

    if text.startswith("$") and text.count("$") >= 2:
        parts = text.split("$")
        algorithm = parts[1]
        candidate = HashCandidate(algorithm, "low", "Generic PHC string, specific algorithm not identified")
        return [candidate]

    if text.count(".") == 2 and text.startswith("eyJ"):
        candidate = HashCandidate("JWT", "low", "this looks like a JWT, not a hash")
        return [candidate]

    if len(text) > 0 and len(text) % 4 == 0 and all(c in BASE64_CHARACTERS for c in text):
        candidate = HashCandidate("Base64", "low", "this looks like base64-encoded data, not a hash")
        return [candidate]
    
    return []

def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Identify the type of a hash")
    parser.add_argument("hash", help="Hash string to identify")
    return parser
