import pytest
import dataclasses
import hash_identifier

def test_hash_candidate_is_frozen():
    hash_candidate = hash_identifier.HashCandidate("MD5", "high", "test")

    
    with pytest.raises(dataclasses.FrozenInstanceError):
        hash_candidate.algorithm = "SHA256"

def test_bcrypt_prefix_is_recognized():
    result = hash_identifier.identify("$2b$12$KIXQ4LxU8wA9z8vQeYb7T")
    assert result[0].algorithm == "bcrypt"
    assert result[0].confidence == "high"

def test_mysql5_shape_is_recognized():
    result = hash_identifier.identify("*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4")
    assert result[0].algorithm == "MySQL4.1/MySQL5"
    assert result[0].confidence == "high"

def test_descrypt_shape_is_recognized():
    result = hash_identifier.identify("abFZSxKKDQ5s6")
    assert result[0].algorithm == "DES crypt"
    assert result[0].confidence == "medium"

def test_32_char_hex_returns_multiple_candidates():
    result = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert len(result) == 4
    assert result[0].algorithm == "MD5"
    assert result[0].confidence == "medium"
    assert result[1].confidence == "low"

def test_hex_length_not_in_table_returns_empty():
    result = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99ab")
    assert result == []

def test_generic_phc_string_is_recognized():
    result = hash_identifier.identify("$unknown$v=19$m=65536,t=3,p=4$c2FsdDEyMw$8K1bG9Z5VQxJ7YwR3nLm2Q")
    assert result[0].algorithm == "unknown"
    assert result[0].confidence == "low"

def test_jwt_is_recognized_as_not_a_hash():
    result = hash_identifier.identify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
    assert result[0].algorithm == "JWT"
    assert result[0].confidence == "low"

def test_base64_without_padding_is_recognized():
    result = hash_identifier.identify("SGVsbG8gV29ybGQh")
    assert result[0].algorithm == "Base64"
    assert result[0].confidence == "low"

def test_empty_string_returns_empty_list():
    result = hash_identifier.identify("")
    assert result == []

def test_pbkdf2_atlassian_prefix_is_recognized():
    result = hash_identifier.identify("$pbkdf2$sha1$10000$salt123$abcdefghijklmnopqrst")
    assert result[0].algorithm == "PBKDF2-SHA1 (Atlassian)"
    assert result[0].confidence == "high"

def test_macos_keychain_prefix_is_recognized():
    result = hash_identifier.identify("$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222")
    assert result[0].algorithm == "macOS/iCloud Keychain"
    assert result[0].confidence == "high"

def test_x_pbkdf2_ldap_prefix_is_recognized():
    result = hash_identifier.identify("{x-pbkdf2}8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B=")
    assert result[0].algorithm == "PBKDF2 (Atlassian)"
    assert result[0].confidence == "high"

def test_solaris_md5_prefix_is_recognized():
    result = hash_identifier.identify("$md5,abcxyz123$8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4=")
    assert result[0].algorithm == "Solaris MD5 crypt"
    assert result[0].confidence == "high"

def test_sha1crypt_prefix_is_recognized():
    result = hash_identifier.identify("$sha1$40000$abcxyz123$8d9f4a5b7e1c2d3f6g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B")
    assert result[0].algorithm == "sha1crypt"
    assert result[0].confidence == "high"