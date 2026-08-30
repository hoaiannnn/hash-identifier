# Hash Identifier

A Python command-line tool for identifying hash-like strings and classifying possible hash algorithms based on their format, length, prefixes, and encoding patterns.

The tool is designed for security learning and practical analysis of unknown hash values. It returns possible algorithms with confidence scores, detection reasons, Hashcat modes, and crack-difficulty information.

---

## 1. Project Overview

Hash Identifier analyzes an input string and determines which hash algorithms it may represent.

The project uses a **table-driven detection approach** combined with a **decision cascade**. Detection rules and algorithm information are stored in reusable mappings, while `identify()` checks different formats in a defined order.

When a format is ambiguous, the tool returns multiple `HashCandidate` objects instead of incorrectly selecting a single algorithm.

For example, a 32-character hexadecimal string may match:

```text
MD5
NTLM
MD4
LM
```

The candidates are returned with different confidence scores.

---

## 2. Features

### Hash Identification

- Detect common hash algorithms based on:
  - prefixes
  - length
  - character patterns
  - known formats

- Detect password-hashing and key-derivation formats such as:
  - bcrypt
  - Argon2
  - scrypt
  - PBKDF2
  - phpass

- Detect special formats such as:
  - MySQL
  - DES crypt
  - LDAP

- Detect encoded or non-hash formats such as:
  - Base32
  - Base58
  - Base64
  - JWT
  - URL
  - hexadecimal values with a `0x` prefix

### Confidence Scoring

Each detection result contains a confidence score between `0.0` and `1.0`.

Each result is represented by a `HashCandidate` containing:

```text
algorithm
confidence
reason
hashcat_mode
crack_difficulty
```

### Hashcat Mode

The tool provides Hashcat modes for supported algorithms.

This allows the identification result to be used as a starting point for further password-security analysis.

### Crack Difficulty

The tool provides an estimated crack difficulty for supported algorithms.

Possible values include:

```text
trivial
moderate
hard
very_hard
```

For bcrypt, the difficulty is determined from its cost parameter.

### Split Mode

The tool can classify fields from structured input as:

```text
username
hash
salt
garbage
```

A custom delimiter can also be specified.

### JSON Output

Detection results can be displayed as JSON for easier processing by other tools or scripts.

### File Input

The tool can read hash values from a file instead of requiring a single value from the command line.

### Pre-commit Hash Detection

The project includes a custom pre-commit checker that scans changed files for high-confidence hash-like strings.

This helps prevent accidentally committing hash values into source code or configuration files.

Intentional test hashes can be ignored by adding:

```text
# pragma: allow-hash
```

to the line containing the hash.

---

## 3. Architecture

The main identification process follows a decision cascade:

```text
Input
  │
  ▼
identify()
  │
  ├── Prefix rules
  │
  ├── Special formats
  │
  ├── Hexadecimal length rules
  │
  ├── Generic PHC / other formats
  │
  └── Non-hash / encoded data
  │
  ▼
List[HashCandidate]
```

The project uses a **table-driven design** instead of putting every detection rule into a large collection of conditional statements.

Important mappings include:

```text
PREFIX_RULES
HEX_LENGTH_RULES
HASHCAT_MODE_BY_ALGORITHM
CRACK_DIFFICULTY_BY_ALGORITHM
```

The identification result is represented by:

```text
HashCandidate
├── algorithm
├── confidence
├── reason
├── hashcat_mode
└── crack_difficulty
```

### Ambiguous Hashes

Some hash formats cannot uniquely identify an algorithm from the string alone.

For example:

```text
5f4dcc3b5aa765d61d8327deb882cf99
```

is a 32-character hexadecimal value and can match multiple algorithms.

Instead of returning only one result, the tool returns multiple candidates with different confidence scores.

This makes the output more useful for further investigation.

### Pre-commit Checker

The pre-commit checker works separately from the main identifier:

```text
Changed file
     │
     ▼
Read each line
     │
     ▼
Skip lines containing # pragma: allow-hash
     │
     ▼
Split line into tokens
     │
     ▼
identify(token)
     │
     ▼
High-confidence hash?
     │
   ┌─┴─┐
  Yes  No
   │    │
   ▼    ▼
Warning  Continue
   │
   ▼
Block commit
```

If a high-confidence hash is found, the checker returns exit code `1`.

If no high-confidence hash is found, it returns exit code `0`.

---

## 4. Installation

### 4.1 Clone the Repository

```bash
git clone <repository-url>
cd hash-identifier
```

### 4.2 Create a Virtual Environment

Creating a virtual environment keeps project dependencies isolated from the system Python installation.

```bash
python -m venv venv
```

### 4.3 Activate the Virtual Environment

For Git Bash on Windows:

```bash
source venv/Scripts/activate
```

For Windows Command Prompt:

```cmd
venv\Scripts\activate
```

After activation, the terminal should show:

```text
(venv)
```

### 4.4 Install Dependencies

```bash
pip install -r requirements.txt
```

The project uses:

- `rich`
- `pytest`
- `pre-commit`

The remaining packages in `requirements.txt` are dependencies required by these packages.

### 4.5 Verify the Installation

Check the command-line interface:

```bash
python hash_identifier.py --help
```

Run the test suite:

```bash
pytest -v
```

Check pre-commit:

```bash
pre-commit --version
```

---

## 5. Usage

### Identify a Hash

```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

The tool displays possible algorithms together with their confidence, reason, Hashcat mode, and crack difficulty.

Because some formats are ambiguous, one input can produce multiple candidates.

### Identify a bcrypt Hash

```bash
python hash_identifier.py '$2b$12$KIXQ4LxU8wA9z8vQeYb7T'
```

### JSON Output

```bash
python hash_identifier.py --json 5f4dcc3b5aa765d61d8327deb882cf99
```

### Read From a File

```bash
python hash_identifier.py --file hash.txt
```

### Split Mode

```bash
python hash_identifier.py --split "administrator:5f4dcc3b5aa765d61d8327deb882cf99:salt123"
```

The default delimiter is `:`.

A custom delimiter can be specified:

```bash
python hash_identifier.py --split --delimiter "," "administrator,hash,salt"
```

### Pre-commit Checker

The checker can be run manually against a file:

```bash
python pre_commit_check.py sample_config.py
```

The checker reads the file line by line, splits each line into tokens, and passes the tokens to `identify()`.

If a high-confidence hash is detected, the command returns exit code `1`.

For example:

```text
Commit blocked — possible hash(es) found:
  sample_config.py:2: <hash> looks like bcrypt
```

Intentional hash values can be excluded with:

```python
test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # pragma: allow-hash
```

### Run Tests

Run all tests:

```bash
pytest -v
```

Run only the pre-commit tests:

```bash
pytest test_pre_commit_check.py -v
```

---

## 6. Folder Structure

```text
hash-identifier/
│
├── .gitignore
├── .pre-commit-hooks.yaml
├── README.md
├── requirements.txt
├── hash.txt
├── sample_config.py
├── hash_identifier.py
├── pre_commit_check.py
├── test_hash_identifier.py
├── test_pre_commit_check.py
│
└── docs/
    └── limitations.md
```

### Main Files

| File                       | Description                                           |
| -------------------------- | ----------------------------------------------------- |
| `hash_identifier.py`       | Core hash identification logic and CLI                |
| `pre_commit_check.py`      | Pre-commit checker for high-confidence hash detection |
| `test_hash_identifier.py`  | Tests for the main hash identification functionality  |
| `test_pre_commit_check.py` | Tests for the pre-commit checker                      |
| `sample_config.py`         | Sample file used when testing the pre-commit checker  |
| `hash.txt`                 | Example hash input file                               |
| `requirements.txt`         | Project dependencies                                  |
| `.pre-commit-hooks.yaml`   | Pre-commit hook definition                            |
| `docs/limitations.md`      | Documentation of known project limitations            |
| `README.md`                | Project documentation                                 |

---

## 7. Tech Stack

| Technology    | Purpose                                  |
| ------------- | ---------------------------------------- |
| Python 3      | Main programming language                |
| `argparse`    | Command-line argument parsing            |
| `dataclasses` | Structured `HashCandidate` objects       |
| `Rich`        | Formatted terminal output                |
| JSON          | Machine-readable output                  |
| `pytest`      | Automated testing                        |
| `tempfile`    | Temporary files used in pre-commit tests |
| `pre-commit`  | Git pre-commit hook framework            |

The project uses Python standard-library modules together with a small number of external packages for terminal output, testing, and Git hook integration.

---

## 8. Future Work

- Improve accuracy for ambiguous hash formats.
- Add support for additional hash and password-hashing formats.
- Improve token extraction in the pre-commit checker.
- Add more tests for false positives and false negatives.
- Improve validation of structured hash formats.
- Make the pre-commit confidence threshold configurable.
- Add continuous integration for automatically running tests.
- Improve CLI error handling and user feedback.
- Add more real-world security-analysis examples.
- Expand documentation with additional usage examples.

---

## License

This project is intended for educational and security-learning purposes.
