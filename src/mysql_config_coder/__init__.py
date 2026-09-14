import argparse
import os
import struct
import tempfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

_VERSION_LENGTH = 4
_LOGIN_KEY_LENGTH = 20
_MAX_CIPHERTEXT_LENGTH = 4096
_LENGTH = struct.Struct("<I")


def realkey(key: bytes) -> bytes:
    """Fold a MySQL login key into a 16-byte AES key.

    Each input byte is XORed into the output position matching its offset
    modulo the AES block size, reproducing MySQL's key derivation.
    """
    result = bytearray(AES.block_size)
    for index, byte in enumerate(key):
        result[index % AES.block_size] ^= byte
    return bytes(result)


def encode_line(plaintext: bytes, real_key: bytes) -> bytes:
    """Pad one plaintext line with PKCS#7 and encrypt it using AES-128-ECB."""
    pad_length = AES.block_size - len(plaintext) % AES.block_size
    padded = plaintext + bytes([pad_length]) * pad_length
    return AES.new(real_key, AES.MODE_ECB).encrypt(padded)


def decode_line(ciphertext: bytes, real_key: bytes) -> bytes:
    """Decrypt one AES-128-ECB record and remove its validated PKCS#7 padding.

    Invalid block lengths and malformed padding raise ``ValueError``.
    """
    if not ciphertext or len(ciphertext) % AES.block_size:
        raise ValueError("invalid encrypted line length")

    plaintext = AES.new(real_key, AES.MODE_ECB).decrypt(ciphertext)
    pad_length = plaintext[-1]
    if (
        not 1 <= pad_length <= AES.block_size
        or plaintext[-pad_length:] != bytes([pad_length]) * pad_length
    ):
        raise ValueError("invalid encrypted line padding")
    return plaintext[:-pad_length]


def encode(data: bytes, key: bytes | None = None) -> bytes:
    """Encode plaintext as a MySQL login-file byte stream.

    The output contains four reserved zero bytes, a 20-byte login key, then
    each plaintext line as a little-endian length followed by encrypted data.
    A random login key is generated when ``key`` is ``None``; supplied keys
    must be exactly 20 bytes. Oversized records raise ``ValueError``.
    """
    if key is None:
        key = get_random_bytes(_LOGIN_KEY_LENGTH)
    if len(key) != _LOGIN_KEY_LENGTH:
        raise ValueError(f"login key must be {_LOGIN_KEY_LENGTH} bytes")

    real_key = realkey(key)
    output = bytearray(_LENGTH.pack(0) + key)
    for line in data.splitlines(keepends=True):
        ciphertext = encode_line(line, real_key)
        if len(ciphertext) > _MAX_CIPHERTEXT_LENGTH:
            raise ValueError("plaintext line exceeds MySQL limit")
        output.extend(_LENGTH.pack(len(ciphertext)))
        output.extend(ciphertext)
    return bytes(output)


def decode(data: bytes) -> bytes:
    """Decode a MySQL login-file byte stream into its original plaintext.

    The header supplies the format version and login key. Each following
    length-prefixed record is decrypted and concatenated. Unsupported,
    truncated, or malformed input raises ``ValueError``.
    """
    if len(data) < _VERSION_LENGTH + _LOGIN_KEY_LENGTH:
        raise ValueError("file is too short")

    version = _LENGTH.unpack_from(data)[0]
    if version != 0:
        raise ValueError(f"unsupported format version: {version}")

    key_start = _VERSION_LENGTH
    offset = key_start + _LOGIN_KEY_LENGTH
    real_key = realkey(data[key_start:offset])
    output = bytearray()
    while offset < len(data):
        if len(data) - offset < _LENGTH.size:
            raise ValueError("truncated encrypted line length")
        length = _LENGTH.unpack_from(data, offset)[0]
        offset += _LENGTH.size
        ciphertext = data[offset : offset + length]
        if len(ciphertext) != length:
            raise ValueError("truncated encrypted line")
        output.extend(decode_line(ciphertext, real_key))
        offset += length
    return bytes(output)


def _write(path: Path, data: bytes) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encode and decode .mylogin.cnf files."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    decode_parser = commands.add_parser("decode", help="decode a .mylogin.cnf file")
    decode_parser.add_argument(
        "infile", nargs="?", default=os.getenv("MYSQL_TEST_LOGIN_FILE")
    )
    decode_parser.add_argument("outfile", type=Path)

    encode_parser = commands.add_parser("encode", help="encode a plaintext file")
    encode_parser.add_argument("infile", type=Path)
    encode_parser.add_argument(
        "outfile", nargs="?", type=Path, default=os.getenv("MYSQL_TEST_LOGIN_FILE")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.infile is None or args.outfile is None:
        parser.error(
            "infile and outfile are required (MYSQL_TEST_LOGIN_FILE may supply one)"
        )

    infile = Path(args.infile)
    transform = decode if args.command == "decode" else encode
    try:
        result = transform(infile.read_bytes())
        _write(args.outfile, result)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0
