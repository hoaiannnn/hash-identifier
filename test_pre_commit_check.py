import tempfile
import os

from pre_commit_check import check_file

def test_check_file_detects_leaked_hash():
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False
    ) as f:
        f.write('password_hash = "$2b$12$KIXQ4LxU8wA9z8vQeYb7T"\n')
        temp_path = f.name

    try:
        warnings = check_file(temp_path)
        assert len(warnings) == 1
        assert "bcrypt" in warnings[0]
    finally:
        os.remove(temp_path)


def test_check_file_respects_allow_hash_pragma():
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False
    ) as f:
        f.write(
            'test_hash = "5f4dcc3b5aa765d61d8327deb882cf99" '
            '# pragma: allow-hash\n'
        )
        temp_path = f.name

    try:
        warnings = check_file(temp_path)
        assert warnings == []
    finally:
        os.remove(temp_path)