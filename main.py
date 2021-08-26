#!/usr/bin/python3
from hashlib import sha256, new
import binascii
import os
import hashlib
import sys


PCURVE = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1  # The proven prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Number of points in the field
ACURVE = 0
BCURVE = 7  # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPOINT = (Gx, Gy)  # This is our generator point. Trillions of dif ones possible




# bytes to read at a time from file (10meg)
readlength=10*1024*1024

#magic = '\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20'
magic = b'\x13\x02\x01\x01\x04\x20'
magiclen = len(magic)



def find_keys(filename):
    keys = set()
    with open(filename, "rb") as f:
        # read through target file one block at a time
        while True:
            data = f.read(readlength)
            if not data:
                break

            # look in this block for keys
            pos = 0
            while True:
                # find the magic number
                pos = data.find(magic, pos)
                if pos == -1:
                    break
                key_offset = pos + magiclen
                key_data = data[key_offset:key_offset + 32]
                keys.add(key_data)
                key_data = int.from_bytes(key_data, byteorder='big', signed=False)
                get_addr(key_data)
                pos += 1

            # are we at the end of the file?
            if len(data) == readlength:
                # make sure we didn't miss any keys at the end of the block
                f.seek(f.tell() - (32 + magiclen))
    return keys

def modinv(a: int, n: int = PCURVE):
    # MAXIMO COMUN DIVISOR: Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1, 0
    resto = a % n
    high = n
    while resto > 1:
        ratio = high // resto
        nm = hm - lm * ratio
        new = high - resto * ratio
        lm, resto, hm, high = nm, new, lm, resto
    return lm % n


def ECadd(a, b):  # Not true addition, invented for EC. Could have been called anything.
    LamAdd = ((b[1] - a[1]) * modinv(b[0] - a[0], PCURVE)) % PCURVE
    x = (LamAdd * LamAdd - a[0] - b[0]) % PCURVE
    y = (LamAdd * (a[0] - x) - a[1]) % PCURVE
    return x, y


def ECdouble(a):  # This is called point doubling, also invented for EC.
    Lam = ((3 * a[0] * a[0] + ACURVE) * modinv((2 * a[1]), PCURVE)) % PCURVE
    x = (Lam * Lam - 2 * a[0]) % PCURVE
    y = (Lam * (a[0] - x) - a[1]) % PCURVE
    return x, y


def EccMultiply(gen_point: tuple, scalar_hex: int):  # Double & add. Not true multiplication
    if scalar_hex == 0 or scalar_hex >= N:
        raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(scalar_hex))[2:]  # string binario sin el comienzo 0b
    Q = gen_point  # esto es una tupla de dos integer del punto de generacion de la curva
    for i in range(1, len(ScalarBin)):
        Q = ECdouble(Q)
        if ScalarBin[i] == "1":
            Q = ECadd(Q, gen_point)  #
    return Q


def private_to_hex_publics(hex_private_key: hex):
    public_key = EccMultiply(GPOINT, hex_private_key)
    public_uncompressed = f"04{hex(public_key[0])[2:].upper()}{hex(public_key[1])[2:].upper()}"

    if public_key[1] % 2 == 1:  # If the Y value for the Public Key is odd.
        public_compressed = ("03" + str(hex(public_key[0])[2:]).zfill(64).upper())
    else:  # Or else, if the Y value is even.
        public_compressed = ("02" + str(hex(public_key[0])[2:]).zfill(64).upper())
    return public_uncompressed, public_compressed


def hash_256_from_hex_string_like_bytes(hexstring: str):
    return sha256(bytes.fromhex(hexstring)).hexdigest()


def ripemd160_from_hex_string_like_bytes(hexstring: str):
    return new('ripemd160', bytes.fromhex(hexstring)).hexdigest()


def b58encode(hex_string, expected_length=None):
    v = binascii.unhexlify(hex_string)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    lev, number = 1, 0
    for char in reversed(v):
        number += lev * char
        lev = lev << 8  # 2^8
    string = ""
    while number:
        number, modulo = divmod(number, 58)
        string = alphabet[modulo] + string
    if not expected_length:
        return string
    elif len(string) != expected_length:
        raise Exception(f"b58encode: Expected length={expected_length} obtained length={len(string)}")
    else:
        return string


def sha256_get_checksum(hex_string_to_checksum):
    hasha1 = hash_256_from_hex_string_like_bytes(hex_string_to_checksum)
    # print("HashA1", hasha1)
    hasha2 = hash_256_from_hex_string_like_bytes(hasha1)
    # print("HashA2", hasha2)
    return hasha2[:8].upper()


def sha_ripe_digest(hex_string_to_checksum):
    hashc1 = hash_256_from_hex_string_like_bytes(hex_string_to_checksum)
    hashc2 = ripemd160_from_hex_string_like_bytes(hashc1)
    return hashc2.upper()


def wif_from_private(privkey: hex):
    # put 80 for bitcoin and concatenate with privkey
    prepend = "80"
    private_key_str = hex(privkey)[2:].zfill(64)
    prepended = (prepend + private_key_str).upper()
    compressed = (prepend + private_key_str + "01").upper()

    if len(prepended) != 66 or len(compressed) != 68:
        raise Exception("WIF conversion: Wrong prepended or compressed private key, length not 66")

    uncompressed_checksum = sha256_get_checksum(prepended)
    compressed_checksum = sha256_get_checksum(compressed)
    private_key_uncompressed_checksum = prepended + uncompressed_checksum
    private_key_compressed_checksum = compressed + compressed_checksum
    private_key_WIF_uncompressed_Base58 = b58encode(private_key_uncompressed_checksum, 51)
    private_key_WIF_compressed_Base58 = b58encode(private_key_compressed_checksum, 52)

    #print("PREPENDED:\t\t\t\t", prepended)
    #print("PRIV_UNCOMP+CHECKSUM:\t\t\t", private_key_uncompressed_checksum)
    #print("Private_key_WIF_uncompressed_Base58:\t", private_key_WIF_uncompressed_Base58)
    #print("PRIV_COMP+CHECKSUM:\t\t\t", private_key_compressed_checksum)
    #print("Private_key_WIF_compressed_Base58:\t", private_key_WIF_compressed_Base58)
    return private_key_WIF_uncompressed_Base58, private_key_WIF_compressed_Base58


def hex_public_to_public_addresses(hex_publics):
    uncompressed = hex_publics[0]
    public_key_hashC_uncompressed = "00" + sha_ripe_digest(uncompressed)
    checksum = sha256_get_checksum(public_key_hashC_uncompressed)
    PublicKeyChecksumC = public_key_hashC_uncompressed + checksum
    public_address_uncompressed = "1" + b58encode(PublicKeyChecksumC, 33)
    #print("Public address uncompressed:\t", public_address_uncompressed)

    compressed = hex_publics[1]
    PublicKeyVersionHashD = "00" + sha_ripe_digest(compressed)
    compressed_checksum = sha256_get_checksum(PublicKeyVersionHashD)
    PublicKeyChecksumC = PublicKeyVersionHashD + compressed_checksum
    public_address_compressed = "1" + b58encode(PublicKeyChecksumC, 33)
    #print("Public address compressed:\t", public_address_compressed)
    return public_address_uncompressed, public_address_compressed


def main():
    if len(sys.argv) != 2:
        print("./{0} <filename>".format(sys.argv[0]))
        exit()

    keys = find_keys(sys.argv[1])

    if len(keys) == 0:
        print("Sorry... Nothing found....")
    else:
        print()
        for key in keys:
            print(key)

def get_addr(privkey):
    print(f"PRIVATE KEY:\t {hex(privkey)[2:].zfill(64).upper()}")

    # Public hex test
    hex_publics = private_to_hex_publics(privkey)
    # print(hex_publics)
    # print()

    # WIF creation test
    wif = wif_from_private(privkey)
    # print(wif)

    # Public keys
    public = hex_public_to_public_addresses(hex_publics)
    print(f"possible privkey: \t 0x{hex(privkey)[2:].zfill(64).upper()}")
    print(f"possible addr:    \t {public[0]}")

if __name__ == "__main__":
    main()