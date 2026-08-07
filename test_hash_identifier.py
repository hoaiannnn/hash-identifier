import pytest
import dataclasses
import hash_identifier

def test_hash_candidate_is_frozen():
    hash_candidate = hash_identifier.HashCandidate("MD5", "high", "test")

    
    with pytest.raises(dataclasses.FrozenInstanceError):
        hash_candidate.algorithm = "SHA256"

