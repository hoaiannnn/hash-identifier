from dataclasses import dataclass, asdict
import argparse
from rich.table import Table
from rich.console import Console
import json
import sys

# global variables
HEX_CHARACTERS = "0123456789abcdefABCDEF"
DESCRYPT_CHARACTERS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
USERNAME_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
BASE32_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE58_CHARACTERS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE64_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

COLOR_BY_CONFIDENCE = {"high": "green", "medium": "yellow", "low": "cyan"}
TYPE_COLOR = {"username": "blue", "hash": "green", "salt": "yellow", "garbage": "red"}
@dataclass(frozen=True)
class HashCandidate:
    algorithm: str
    confidence: float
    reason: str
    hashcat_mode: int | None = None

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.8:
            return "high"
        elif self.confidence >= 0.5:
            return "medium"
        else:
            return "low"

PREFIX_RULES: dict[str, tuple[str, str]] = {
    # Argon2
    "$argon2d$": "Argon2d",
    "$argon2i$": "Argon2i",
    "$argon2id$": "Argon2id",

    # bcrypt
    "$2$": "bcrypt (original)",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
    "$2x$": "bcrypt",

    # PBKDF2
    "pbkdf2_sha256$": "PBKDF2-HMAC-SHA256 (Django)",
    "pbkdf2_sha1$": "PBKDF2-HMAC-SHA1 (Django)",
    "argon2$": "Argon2 (Django)",
    "bcrypt_sha256$": "bcrypt-SHA256 (Django)",
    "bcrypt$": "bcrypt (Django)",
    "scrypt$": "scrypt (Django)",

    # Unix crypt(3) family
    "$6$": "SHA-512 crypt",
    "$5$": "SHA-256 crypt",
    "$1$": "MD5 crypt",
    "$apr1$": "Apache MD5 (APR1)",

    # phpass
    "$P$": "phpass Portable",
    "$H$": "phpass (phpBB)",
    
    # Hash Function
    "{MD5}": "LDAP MD5",
    "{SMD5}": "LDAP SMD5",
    "{SHA}": "LDAP SHA",
    "{SSHA}": "LDAP SSHA",

    "$pbkdf2$": "PBKDF2-SHA1 (Atlassian)",
    "$ml$": "macOS/iCloud Keychain",
    "{x-pbkdf2}": "PBKDF2 (Atlassian)",
    "$sha1$": "sha1crypt",
    "$md5,": "Solaris MD5 crypt",
}

HASHCAT_MODE_BY_ALGORITHM: dict[str, int | None] = {
    "MD4": 900,                               
    "MD5": 0,                                
    "SHA-1": 100,                             
    "SHA-224": 1300,                           
    "SHA-256": 1400,                          
    "SHA-384": 10800,                           
    "SHA-512": 1700,                            

    # SHA-3
    "SHA3-224": 17300,
    "SHA3-256": 17400,
    "SHA3-384": 17500,
    "SHA3-512": 17600,

    # Keccak
    "Keccak-224": 17700,
    "Keccak-256": 17800,
    "Keccak-384": 17900,
    "Keccak-512": 18000,

    # BLAKE
    "BLAKE2b-512": 600,                       
    "BLAKE2s-256": 31000,

    # Legacy / special
    "LM": 3000,                             
    "NTLM": 1000,                              
    "CRC32": 11500,                            

    # Other hash functions
    "RIPEMD-160": 6000,
    "Whirlpool": 6100,
    "GOST R 34.11-2012 (256-bit)": 11700,
    "GOST R 34.11-2012 (512-bit)": 11800,
    "SM3": 31100,

    # Password hashing / KDF
    "bcrypt": 3200,                            
    "scrypt": 8900,                           
    "Argon2": 34000,                          
    "PBKDF2-HMAC-SHA1": 12001,
    "PBKDF2-HMAC-SHA256": 10900,
    "PBKDF2-HMAC-SHA512": 12100,

    # phpass
    "phpass": 400,                              

    # Unix crypt
    "MD5 crypt": 500,                         
    "SHA-256 crypt": 7400,                      
    "SHA-512 crypt": 1800,                    

    # LDAP
    "LDAP MD5": 111,
    "LDAP SHA": 101,

    # Extended for PREFIX_RULES
    "Argon2d": 15900,
    "Argon2i": 15700,
    "Argon2id": 15800,
    "bcrypt (original)": 3200,
    "PBKDF2-HMAC-SHA256 (Django)": 10000,      
    "PBKDF2-HMAC-SHA1 (Django)": 11000,         
    "Argon2 (Django)": 15800,                 
    "bcrypt-SHA256 (Django)": None,
    "bcrypt (Django)": 3200,
    "scrypt (Django)": 8900,
    "Apache MD5 (APR1)": 1600,         
    "phpass Portable": 400,
    "phpass (phpBB)": 400,
    "LDAP SMD5": 111,
    "LDAP SSHA": 101,
    "PBKDF2-SHA1 (Atlassian)": 12001,
    "macOS/iCloud Keychain": None,
    "PBKDF2 (Atlassian)": 12001,
    "sha1crypt": None,
    "Solaris MD5 crypt": 7000,

    # Extended for special detections
    "MySQL4.1/MySQL5": 300,                     
    "DES crypt": 1500,                          
    "Tiger-128": None,                         
    "GOST R 34.11-94": 6900,         
}

HEX_LENGTH_RULES: dict[int, list[str]] = {
    8: ["CRC32"],
    24: ["Tiger-128"],
    32: ["MD5", "NTLM", "MD4", "LM"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224"],
    64: ["SHA-256", "SM3", "GOST R 34.11-94"],
    96: ["SHA-384"],
    128: ["SHA-512", "Whirlpool"],
}

# Helper validators
def _is_hex(s: str) -> bool:
    if len(s) <= 0:
        return False
    return all(c in HEX_CHARACTERS for c in s)

def _is_base32(s: str) -> bool:
    if not s:
        return False

    data = s.rstrip("=")

    if "=" in data:
        return False

    if not all(c in BASE32_CHARACTERS for c in data):
        return False

    if "=" in s and not s.startswith(data):
        return False

    if "=" in s and len(s) % 8 != 0:
        return False

    return True

def _is_base58(s: str) -> bool:
    if not s:
        return False

    return all(c in BASE58_CHARACTERS for c in s)

def _is_base64(s: str) -> bool:
    if not s:
        return False

    if len(s) % 4 != 0:
        return False

    if "=" in s:
        padding_start = s.find("=")

        if not all(c == "=" for c in s[padding_start:]):
            return False

        if len(s) - padding_start > 2:
            return False

    return all(c in BASE64_CHARACTERS or c == "=" for c in s)

def _is_mysql5(s: str) -> bool:
    if len(s[1:]) == 40 and s.startswith("*") and _is_hex(s[1:]):
        return True
    return False

def _is_descrypt(s: str) -> bool:
    if len(s) == 13 and all(c in DESCRYPT_CHARACTERS for c in s):
        return True
    return False

# Candidate helper
def _candidate(algorithm: str, confidence: float, reason: str) -> HashCandidate:
    return HashCandidate(algorithm=algorithm, confidence=confidence, reason=reason, hashcat_mode=HASHCAT_MODE_BY_ALGORITHM.get(algorithm))

def identify(text: str) -> list[HashCandidate]:
    # 1. Strong detection: prefix
    for prefix, algorithm in PREFIX_RULES.items():
        if text.startswith(prefix):
            return [_candidate(algorithm, 0.95, f"matched prefix '{prefix}'")]

    # 2. Strong / special formats
    if _is_mysql5(text):
        return [_candidate("MySQL4.1/MySQL5", 0.85, "matched MySQL 4.1/MySQL5 hash format")]
    
    if _is_descrypt(text):
        return [_candidate("DES crypt", 0.70, "matched DES crypt hash format")]

    # 3. Hexadecimal hashes
    if _is_hex(text) and len(text) in HEX_LENGTH_RULES.keys():
        x = HEX_LENGTH_RULES[len(text)]
        candidates = []

        for index, algorithm in enumerate(x):
            if index == 0:
                confidence = 0.55
                reason = (f"{len(text)} hex chars, most common")
            else:
                confidence = 0.55 / (index + 1)
                reason = (f"{len(text)} hex chars, less common")

            candidates.append(_candidate(algorithm, confidence, reason))

        return candidates

    # 4. Generic PHC string
    if text.startswith("$") and text.count("$") >= 2:
        parts = text.split("$")
        algorithm = parts[1]
        return [_candidate(algorithm, 0.30, "Generic PHC string, specific algorithm not identified")]

    # 5. URL
    if text.startswith("http://") or text.startswith("https://"):
        return [_candidate("URL", 0.30, "this looks like a URL, not a hash")]
    
     # 6. Hex with 0x prefix
    if text.startswith("0x") and _is_hex(text[2:]):
        return [_candidate("Hex with 0x prefix", 0.30, "this looks like a hex address (Ethereum, memory), not a hash")]

    # 7. JWT
    if text.count(".") == 2 and text.startswith("eyJ"):
        return [_candidate("JWT", 0.30, "this looks like a JWT, not a hash")]

    # 8. Encoded data
    encoding_candidates = []

    if 8 <= len(text) and _is_base32(text):
        encoding_candidates.append(_candidate("Base32", 0.3, "this looks like Base32-encoded data not a hash"))

    if 25 <= len(text) <= 34 and not _is_hex(text) and _is_base58(text):
        encoding_candidates.append(_candidate("Base58", 0.3, "this looks like Base58-encoded data not a hash"))

    if _is_base64(text):
        encoding_candidates.append(_candidate("Base64", 0.3, "this looks like Base64-encoded data not a hash"))

    if encoding_candidates:
        return encoding_candidates

    # 9. No match
    return []

def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Identify the type of a hash")
    parser.add_argument("hash", nargs="*", help="Hash string to identify")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
    parser.add_argument("--file", help="Read a file")
    parser.add_argument("--split", action="store_true", help="Classify each line as username/hash/salt/garbage")
    parser.add_argument("--delimiter", default=":", help="Delimiter for split mode")
    return parser

def _render_table(candidates: list[HashCandidate], console: Console) -> None:
    table = Table()
    table.add_column("algorithm", style="cyan", no_wrap=True)
    table.add_column("confidence")
    table.add_column("reason", style="white")

    if not candidates:
        table.add_row("—", "[yellow]No result[/yellow]", "—")
    else:
        for cand in candidates:
            label = cand.confidence_label   
            color = COLOR_BY_CONFIDENCE.get(label, "white")
            confidence_colored = f"[{color}]{label}[/{color}]"
            table.add_row(cand.algorithm, confidence_colored, cand.reason)

    console.print(table)

def _looks_like_username(s: str) -> bool:
    if len(s) == 0:
        return False

    if _is_hex(s):
        return False

    return all(c in USERNAME_CHARACTERS for c in s)

def classify_field(field: str) -> tuple[str, str]:
    if _looks_like_username(field):
        return ("username", "Looks like a username: alphanumeric, not hex")

    candidates = identify(field)
    if candidates and candidates[0].confidence >= 0.5:
        top = candidates[0]
        return ("hash", f"{top.algorithm} ({top.confidence_label})")

    if 4 <= len(field) <= 16:
        return ("salt", f"{len(field)} chars, short - possibly a salt")

    return ("garbage", "Does not match username, hash or salt pattern")

def _render_split_table(fields: list[str], console: Console) -> None:
    table =Table()
    table.add_column("field", style="cyan", no_wrap=True)
    table.add_column("type")
    table.add_column("reason", style="white")

    for field in fields:
        field_type, reason = classify_field(field)
        color = TYPE_COLOR.get(field_type, "white")
        type_colored = f"[{color}]{field_type}[/{color}]"
        table.add_row(field, type_colored, reason)

    console.print(table)

def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    if args.hash:
        hashes = args.hash
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        if sys.stdin.isatty():
            parser.print_help()
            return 0
        hashes = [line.strip() for line in sys.stdin if line.strip()]

    console = Console()

    if args.split:
        delimiter = args.delimiter
        for line in hashes:
            fields = line.split(delimiter)
            print(f"\nLine: {line}")
            _render_split_table(fields, console)

        return 0

    results = []

    for hash_value in hashes:
        candidates = identify(hash_value)

        results.append({"input": hash_value, "candidates": candidates})

    if args.json:
        output = {
            "result": [
                {
                    "input":result["input"],
                    "candidates": [asdict(candidate) for candidate in result["candidates"]],
                }
            for result in results
            ]
        }

        print(json.dumps(output, indent=2))
    else:
        for result in results:
            print(f"\nHash: {result['input']}")
            _render_table(result["candidates"], console)

    if not any(result["candidates"] for result in results):
        return 1
    return 0

if __name__ == "__main__":
    exit(main())