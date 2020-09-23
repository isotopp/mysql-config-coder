#! /usr/bin/env python3

import click
import struct
from os import urandom

from Crypto.Cipher import AES

_VERSION_LENGTH = 4
_LOGIN_KEY_LENGTH = 20

_CIPHERTEXT_LENGTH = 4


def realkey(key):
    """Create the AES key from the login key."""
    rkey = bytearray(16)
    for i in range(len(key)):
        rkey[i % 16] ^= key[i]
    return bytes(rkey)


def encode_line(plaintext, real_key, buf_len):
    text_len = len(plaintext)
    pad_len  = buf_len - text_len
    pad_chr  = bytes(chr(pad_len), "utf8")

    plaintext = bytes(plaintext) + pad_chr * pad_len

    cipher = AES.new(real_key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def decode_line(ciphertext, real_key):
    cipher = AES.new(real_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    try:
        pad_len = ord(plaintext[-1:])
    except TypeError:
        return None

    if pad_len > len(plaintext):
        return None
   
    return plaintext[:-pad_len]


@click.group(help="Encode and decode mylogin.cnf files.")
def coder():
    pass


@coder.command()
@click.argument("infile", envvar="MYSQL_TEST_LOGIN_FILE", type=click.File("rb"))
@click.argument("outfile", type=click.File("wb", atomic=True))
def decode(infile, outfile):
    """ Decode infile into outfile """
    (version,) = struct.unpack("i", infile.read(_VERSION_LENGTH))

    key = bytearray(infile.read(_LOGIN_KEY_LENGTH))
    real_key = realkey(key)

    while rlen := infile.read(_CIPHERTEXT_LENGTH):
        len, = struct.unpack("I", rlen)
        ciphertext = infile.read(len)
        line = decode_line(ciphertext, real_key)
        outfile.write(line)


@coder.command()
@click.argument("infile", type=click.File("rb"))
@click.argument(
    "outfile", envvar="MYSQL_TEST_LOGIN_FILE", type=click.File("wb", atomic=True)
)
def encode(infile, outfile):
    """ encode infile into outfile """
    key = bytes(
        b"\x02\x0c\x18\x01\x08\x00\x0f\r\x17\x1c\n\x00\x07\x0b\x0c\x0b\x0e\x08\n\x12"
    )
    key = urandom(_LOGIN_KEY_LENGTH)
    real_key = realkey(key)

    outfile.write(struct.pack("I", 0))
    outfile.write(key)

    while line := infile.readline():
        real_len = len(line)
        pad_len = (int(real_len / 16) + 1) * 16

        outfile.write(struct.pack("I", pad_len))
        x = encode_line(line, real_key, pad_len)
        outfile.write(x)


coder()
