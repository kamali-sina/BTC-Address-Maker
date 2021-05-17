import secrets
import codecs
import ecdsa
import hashlib
from collections import deque 

TEST_NET_NETWORK_BYTE = '6f'
TEST_NET_VERSION_BYTE = 'ef'
COMPRESSION_BYTE = '01'
SEGWIT_VERSION_BYTE = '00'
HRP = 'tb'
BECH32_SEPERATOR = '1'

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convert8bits(key, To):
    data = codecs.decode(key, 'hex')
    number = int.from_bytes(data, 'big')
    ret = ''
    th = (1 << To) - 1
    while number:
        x = str(hex(number & th))
        x = x[2:]
        if(len(x) == 1):
            x = '0' + x
        ret = x + ret
        number >>= To
    return ret

def convert8bit_list(key, To):
    data = codecs.decode(key, 'hex')
    number = int.from_bytes(data, 'big')
    ret = []
    th = (1 << To) - 1
    while number:
        ret = [number & th] + ret
        number >>= To
    return ret

def get_bech32_encoded_data(extended_key):
    chars = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    encoded_bech32 = ''
    for item in extended_key:
        encoded_bech32 = encoded_bech32 + chars[item]
    return encoded_bech32

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    address_int = int(address_hex, 16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def get_checksum(key):
    key_bytes = codecs.decode(key, 'hex')
    sha256_nbpk = hashlib.sha256(key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    return str(checksum)[2:-1]

def get_private_key():
    bits = secrets.randbits(256)
    bits_hex = hex(bits)
    private_key = bits_hex[2:]
    lenght = len(private_key)
    if (lenght < 64):
        private_key = ('0' * (64 - lenght)) + private_key
    return private_key

def get_wif_key(private_key):
    extended_key = TEST_NET_VERSION_BYTE + private_key + COMPRESSION_BYTE
    extendedchecksum = extended_key + get_checksum(extended_key)
    wif = base58(extendedchecksum)
    return wif

def get_public_key(private_key):
    private_key_bytes = private_key
    if (type(private_key) != bytes):
        private_key_bytes = codecs.decode(private_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    key_string = str(key_hex)
    return key_string[2:-1]

def get_compressed_public_key(private_key):
    key = str(get_public_key(private_key))
    compressed_key = key[:len(key)//2]
    if (int('0x'+key[-1],16) % 2 == 0):
        return '02' + compressed_key
    return '03' + compressed_key

def get_encrypted_public_key(compressed_key):
    public_key_bytes = codecs.decode(compressed_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    return str(ripemd160_bpk_hex)[2:-1]

def get_wallet_address(compressed_key):
    encrypted_key = get_encrypted_public_key(compressed_key)
    encrypted_key = TEST_NET_NETWORK_BYTE + encrypted_key
    checksum = get_checksum(encrypted_key)
    wallet_address = encrypted_key + checksum
    return base58(wallet_address)

def get_segwit_address(compressed_key):
    encrypted_key = get_encrypted_public_key(compressed_key)
    converted_key = convert8bit_list(encrypted_key, 5)
    converted_key = [int(SEGWIT_VERSION_BYTE)] + converted_key
    checksum = bech32_create_checksum(HRP, converted_key)
    extended_key = converted_key + checksum
    return HRP + BECH32_SEPERATOR + get_bech32_encoded_data(extended_key)