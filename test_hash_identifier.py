import pytest
import dataclasses
import hash_identifier

def test_hash_candidate_is_frozen():
    hash_candidate = hash_identifier.HashCandidate("MD5", 0.95, "test")

    
    with pytest.raises(dataclasses.FrozenInstanceError):
        hash_candidate.algorithm = "SHA256"

def test_bcrypt_prefix_is_recognized():
    result = hash_identifier.identify("$2b$12$KIXQ4LxU8wA9z8vQeYb7T")
    assert result[0].algorithm == "bcrypt"
    assert result[0].confidence == 0.95

def test_mysql5_shape_is_recognized():
    result = hash_identifier.identify("*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4")
    assert result[0].algorithm == "MySQL4.1/MySQL5"
    assert result[0].confidence == 0.85

def test_descrypt_shape_is_recognized():
    result = hash_identifier.identify("abFZSxKKDQ5s6")
    assert result[0].algorithm == "DES crypt"
    assert result[0].confidence == 0.70

def test_32_char_hex_returns_multiple_candidates():
    result = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert len(result) == 4
    assert result[0].algorithm == "MD5"
    assert result[0].confidence == 0.55
    assert result[1].confidence == 0.275
    assert result[1].confidence == 0.275

def test_hex_length_not_in_table_returns_empty():
    result = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99ab")
    assert result == []

def test_generic_phc_string_is_recognized():
    result = hash_identifier.identify("$unknown$v=19$m=65536,t=3,p=4$c2FsdDEyMw$8K1bG9Z5VQxJ7YwR3nLm2Q")
    assert result[0].algorithm == "unknown"
    assert result[0].confidence == 0.3

def test_jwt_is_recognized_as_not_a_hash():
    result = hash_identifier.identify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
    assert result[0].algorithm == "JWT"
    assert result[0].confidence == 0.30

def test_base64_without_padding_is_recognized():
    result = hash_identifier.identify("SGVsbG8gV29ybGQh")
    assert result[0].algorithm == "Base64"
    assert result[0].confidence == 0.30

def test_empty_string_returns_empty_list():
    result = hash_identifier.identify("")
    assert result == []

def test_pbkdf2_atlassian_prefix_is_recognized():
    result = hash_identifier.identify("$pbkdf2$sha1$10000$salt123$abcdefghijklmnopqrst")
    assert result[0].algorithm == "PBKDF2-SHA1 (Atlassian)"
    assert result[0].confidence == 0.95

def test_macos_keychain_prefix_is_recognized():
    result = hash_identifier.identify("$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222")
    assert result[0].algorithm == "macOS/iCloud Keychain"
    assert result[0].confidence == 0.95

def test_x_pbkdf2_ldap_prefix_is_recognized():
    result = hash_identifier.identify("{x-pbkdf2}8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B=")
    assert result[0].algorithm == "PBKDF2 (Atlassian)"
    assert result[0].confidence == 0.95

def test_solaris_md5_prefix_is_recognized():
    result = hash_identifier.identify("$md5,abcxyz123$8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4=")
    assert result[0].algorithm == "Solaris MD5 crypt"
    assert result[0].confidence == 0.95

def test_sha1crypt_prefix_is_recognized():
    result = hash_identifier.identify("$sha1$40000$abcxyz123$8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B")
    assert result[0].algorithm == "sha1crypt"
    assert result[0].confidence == 0.95

def test_tiger128_length_returns_tiger128():
    result = hash_identifier.identify("a1f4c8d2e9b3a7c5d6e8f0a1")
    assert len(result) == 1
    assert result[0].algorithm == "Tiger-128"
    assert result[0].confidence == 0.55

def test_24_char_non_hex_does_not_match_tiger128():
    result = hash_identifier.identify("a1f4c8d2e9b3a7c5d6e8f0gg") 
    assert result[0].algorithm != "Tiger-128"

def test_classify_field_username_returns_username():
    field_type, reason = hash_identifier.classify_field("hoaian")
    assert field_type == "username"
    assert reason == "Looks like a username: alphanumeric, not hex"


def test_classify_field_hash_returns_hash():
    field_type, _ = hash_identifier.classify_field("$2b$12$KIXQ4LxU8wA9z8vQeYb7T")
    assert field_type == "hash"


def test_classify_field_salt_returns_salt():
    field_type, reason = hash_identifier.classify_field("s3cr3t!")
    assert field_type == "salt"
    assert reason == "7 chars, short - possibly a salt"


def test_classify_field_garbage_returns_garbage():
    field_type, reason = hash_identifier.classify_field("1234567890123456789!")
    assert field_type == "garbage"
    assert reason == "Does not match username, hash or salt pattern"


def test_classify_field_administrator_is_username_not_hash():
    field_type, reason = hash_identifier.classify_field("administrator")
    assert field_type == "username"
    assert reason == "Looks like a username: alphanumeric, not hex"

def test_url_is_recognized_as_not_a_hash():
    result = hash_identifier.identify("https://example.com/path")
    assert result[0].algorithm == "URL"

def test_hex_with_0x_prefix_is_recognized():
    result = hash_identifier.identify("0x5f4dcc3b5aa765d61d8327deb882cf99")
    assert result[0].algorithm == "Hex with 0x prefix"

def test_base32_is_recognized():
    result = hash_identifier.identify("JBSWY3DPEBLW64TMMQ======")
    assert result[0].algorithm == "Base32"
    assert result[0].confidence == 0.3
    assert result[0].reason == "this looks like Base32-encoded data not a hash"

def test_base58_is_recognized():
    result = hash_identifier.identify("3MN5qK7xR9vT2pL8wY4cD6sH1")
    assert result[0].algorithm == "Base58"
    assert result[0].confidence == 0.3
    assert result[0].reason == "this looks like Base58-encoded data not a hash"