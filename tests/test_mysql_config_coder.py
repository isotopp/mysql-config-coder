import os
import stat

import pytest

from mysql_config_coder import decode, encode, main


def test_round_trip() -> None:
    plaintext = b"[client]\nuser=root\npassword=secret\n"

    encoded = encode(plaintext, key=bytes(range(20)))

    assert encoded[:24] == bytes(4) + bytes(range(20))
    assert decode(encoded) == plaintext


def test_decode_rejects_truncated_data() -> None:
    encoded = encode(b"user=root\n", key=bytes(20))

    with pytest.raises(ValueError, match="truncated encrypted line"):
        decode(encoded[:-1])


def test_cli_uses_mysql_test_login_file(tmp_path, monkeypatch) -> None:
    plaintext = tmp_path / "plain.cnf"
    encoded = tmp_path / ".mylogin.cnf"
    decoded = tmp_path / "decoded.cnf"
    plaintext.write_bytes(b"[client]\npassword=secret\n")
    monkeypatch.setenv("MYSQL_TEST_LOGIN_FILE", str(encoded))

    assert main(["encode", str(plaintext)]) == 0
    assert main(["decode", str(decoded)]) == 0
    assert decoded.read_bytes() == plaintext.read_bytes()


def test_encode_creates_private_output(tmp_path) -> None:
    plaintext = tmp_path / "plain.cnf"
    encoded = tmp_path / ".mylogin.cnf"
    plaintext.write_bytes(b"[client]\npassword=secret\n")
    old_umask = os.umask(0)
    try:
        assert main(["encode", str(plaintext), str(encoded)]) == 0
    finally:
        os.umask(old_umask)

    assert stat.S_IMODE(encoded.stat().st_mode) == 0o600
