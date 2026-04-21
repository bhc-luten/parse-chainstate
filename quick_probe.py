#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, '/Volumes/mini-ext/btc-utxo-match')
from plyvel import DB  # type: ignore


def enc_varint(n: int) -> bytes:
    tmp = [n & 0x7F]
    n >>= 7
    while n:
        n -= 1
        tmp.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(tmp))


def xor_obfuscate(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def read_varint(buf: bytes, pos: int):
    n = 0
    while True:
        ch = buf[pos]
        pos += 1
        n = (n << 7) | (ch & 0x7F)
        if ch & 0x80:
            n += 1
        else:
            return n, pos


def decompress_amount(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e:
        n *= 10
        e -= 1
    return n


def decompress_script(buf: bytes, pos: int):
    nsize, pos = read_varint(buf, pos)
    if nsize == 0:
        h = buf[pos:pos+20]
        pos += 20
        return bytes([0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac]), pos
    if nsize == 1:
        h = buf[pos:pos+20]
        pos += 20
        return bytes([0xa9, 0x14]) + h + bytes([0x87]), pos
    if nsize in (2, 3):
        x = buf[pos:pos+32]
        pos += 32
        return bytes([33, nsize]) + x + bytes([0xac]), pos
    if nsize in (4, 5):
        x = buf[pos:pos+32]
        pos += 32
        return bytes([nsize]) + x, pos
    script_len = nsize - 6
    script = buf[pos:pos+script_len]
    pos += script_len
    return script, pos


def decode_value(raw: bytes):
    code, pos = read_varint(raw, 0)
    height = code >> 1
    coinbase = code & 1
    amount_code, pos = read_varint(raw, pos)
    amount = decompress_amount(amount_code)
    script, pos = decompress_script(raw, pos)
    return height, coinbase, amount, script.hex()


def main():
    db_path = Path('/Volumes/mini-ext/btc-utxo-match/work/chainstate-copy')
    db = DB(str(db_path), create_if_missing=False)
    ob_key_raw = db.get(bytes.fromhex('0e006f62667573636174655f6b6579'))
    if ob_key_raw is None:
        raise SystemExit('missing obfuscation key')
    ob_key = ob_key_raw[1:]
    print('obfuscation_key', ob_key.hex())

    for k, v in db:
        if k[:1] != b'C':
            continue
        plain = xor_obfuscate(v, ob_key)
        height, coinbase, amount, script_hex = decode_value(plain)
        txid = k[1:33][::-1].hex()
        print({'txid': txid, 'key_tail_hex': k[33:].hex(), 'height': height, 'coinbase': coinbase, 'amount': amount, 'script_pubkey': script_hex})
        break


if __name__ == '__main__':
    main()
