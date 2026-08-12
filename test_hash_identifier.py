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