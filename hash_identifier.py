from dataclasses import dataclass

@dataclass(frozen=True)
class HashCandidate:
    algorithm: str
    confidence: str
    reason: str

PREFIX_RULES = {
    # Argon2
    "$argon2d$": ("Argon2d", "Medium"),
    "$argon2i$": ("Argon2i", "Medium"),
    "$argon2id$": ("Argon2id", "High"),

    # bcrypt
    "$2$": ("bcrypt (original)", "Low"),
    "$2a$": ("bcrypt", "Medium"),
    "$2b$": ("bcrypt", "High"),
    "$2y$": ("bcrypt", "Medium"),
    "$2x$": ("bcrypt", "Low"),

    # PBKDF2
    "pbkdf2_sha256$": ("PBKDF2-HMAC-SHA256 (Django)", "High"),
    "pbkdf2_sha1$": ("PBKDF2-HMAC-SHA1 (Django)", "Medium"),
    "argon2$": ("Argon2 (Django)", "Medium"),
    "bcrypt_sha256$": ("bcrypt-SHA256 (Django)", "Medium"),
    "bcrypt$": ("bcrypt (Django)", "Low"),
    "scrypt$": ("scrypt (Django)", "Low"),

    # Unix crypt(3) family
    "$6$": ("SHA-512 crypt", "High"),
    "$5$": ("SHA-256 crypt", "High"),
    "$1$": ("MD5 crypt", "High"),

    # phpass
    "$P$": ("phpass Portable", "High"),
    "$H$": ("phpass (phpBB)", "Medium"),
    
    # Hash Function
    "{MD5}": ("LDAP MD5", "High"),
    "{SMD5}": ("LDAP SMD5", "High"),
    "{SHA}": ("LDAP SHA", "High"),
    "{SSHA}": ("LDAP SSHA", "High"),
}
    
