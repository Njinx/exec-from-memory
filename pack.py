#!/usr/bin/env python3

import typing as t
import os
import sys
import io
import binascii
import argparse
import string
from collections.abc import Sequence

from Crypto.Cipher import AES as aes


FILE_PREFIX = 'payload'

argparser: argparse.ArgumentParser
args: argparse.Namespace


def parse_args() -> None:
    global argparser
    global args

    argparser = argparse.ArgumentParser()
    argparser.add_argument('--input', '-i', type=str, required=True, nargs='?')
    argparser.add_argument('--outdir', '-o', type=str, required=True, nargs='?')
    argparser.add_argument('--key', '-k', type=str, required=True, nargs='?')

    args = argparser.parse_args()


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    # padded = aes_pad(plaintext, aes.block_size)
    plaintext += bytearray(len(plaintext) % aes.block_size)

    try:
        cipher = aes.new(key, aes.MODE_ECB)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        exit(1)

    return cipher.encrypt(plaintext)


def emit_c_private_headers(c_wtr: io.StringIO) -> None:
    c_wtr.write('#include <stddef.h>\n')


def emit_c_header_guard_begin(h_wtr: io.StringIO, ident: str) -> None:
    h_wtr.write(f'#ifndef {ident}\n')


def emit_c_header_guard_end(h_wtr: io.StringIO, ident: str) -> None:
    h_wtr.write(f'#endif /* {ident} */\n')


T_Emit_C_Array_CB = t.Callable[[t.Any], str]


# https://stackoverflow.com/a/68809518
def escape_c_string(input: str) -> str:
    output = []
    for ch in input:
        if ch == '\\': output.append('\\\\')
        elif ch == '?': output.append('\\?')
        elif ch == '\'': output.append('\\\'')
        elif ch == '"': output.append('\\\"')
        elif ch == '\a': output.append('\\a')
        elif ch == '\b': output.append('\\b')
        elif ch == '\f': output.append('\\f')
        elif ch == '\n': output.append('\\n')
        elif ch == '\r': output.append('\\r')
        elif ch == '\t': output.append('\\t')
        elif ch == '\v': output.append('\\v')
        elif ch in string.printable: output.append(ch)
        else:
            # TODO: What is happening here?
            x = "\\%03o" % ch
            output.append(x if ch>=64 else (("\\%%0%do" % (1+ch>=8)) % ch, x))

    out_str = ''.join(output)
    return f'"{out_str}"'


def _emit_c_array_helper(
    _cb: T_Emit_C_Array_CB,
    c_wtr: io.StringIO,
    h_wtr: io.StringIO,
    c_ident: str,
    c_decl: str,
    data: Sequence,
    multiline: bool,
    entries_per_line: int,
) -> None:
    c_size_decl = f'const size_t {c_ident}_len'
    c_wtr.write(f'{c_size_decl} = {len(data)};\n')

    c_wtr.write(f'{c_decl} = {{')
    if multiline:
        c_wtr.write('\n\t')

    for i, b in enumerate(data):
        c_wtr.write(_cb(b))
        if i != len(data) - 1:
            if multiline and i != 0 and i % entries_per_line == entries_per_line-1:
                c_wtr.write(',\n\t')
            else:
                c_wtr.write(', ')
    c_wtr.write('};\n')

    h_wtr.write(f'extern {c_size_decl};\n')
    h_wtr.write(f'extern {c_decl};\n')


def emit_c_array_from_bytes(
    c_wtr: io.StringIO,
    h_wtr: io.StringIO,
    c_ident: str,
    c_decl: str,
    data: bytes,
    multiline: bool = False,
    entries_per_line: int = 16,
) -> None:
    cb = lambda x: '0x{:02x}'.format(x)
    _emit_c_array_helper(
        cb,
        c_wtr, h_wtr,
        c_ident, c_decl,
        data,
        multiline = multiline,
        entries_per_line = entries_per_line,
    )


def emit_c_array_from_string_list(
    c_wtr: io.StringIO,
    h_wtr: io.StringIO,
    c_ident: str,
    c_decl: str,
    arr: t.List[str],
    multiline: bool = False,
    entries_per_line: int = 4,
) -> None:
    cb = lambda x: '0x0' if x is None else escape_c_string(x)
    _emit_c_array_helper(
        cb,
        c_wtr, h_wtr,
        c_ident, c_decl,
        arr,
        multiline = multiline,
        entries_per_line = entries_per_line,
    )


def emit_c_primitive(
    c_wtr: io.StringIO,
    h_wtr: io.StringIO,
    c_decl: str,
    data: int | float
) -> None:
    c_wtr.write(f'{c_decl} = {data};')
    h_wtr.write(f'extern {c_decl};')


def main() -> None:
    parse_args()

    try:
        os.stat(args.input)
    except FileNotFoundError:
        argparser.print_usage(sys.stderr)
        sys.exit(1)

    key = binascii.unhexlify(args.key)

    plaintext: bytes
    with open(args.input, 'rb') as src_fp:
        plaintext = src_fp.read()

    ciphertext = encrypt(plaintext, key)

    c_path = os.path.join(args.outdir, f'{FILE_PREFIX}.c')
    h_path = os.path.join(args.outdir, f'{FILE_PREFIX}.h')
    dst_c_fp = open(c_path, 'w')
    dst_h_fp = open(h_path, 'w')

    header_ident = '__PAYLOAD_H'
    emit_c_private_headers(dst_c_fp)
    emit_c_header_guard_begin(dst_h_fp, header_ident)
    emit_c_array_from_bytes(dst_c_fp, dst_h_fp,
        'aes_key', 'const unsigned char aes_key[]', key, multiline=True)
    emit_c_primitive(dst_c_fp, dst_h_fp, 'const size_t plaintext_len', len(plaintext))
    emit_c_array_from_bytes(dst_c_fp, dst_h_fp,
        'payload_data', 'const unsigned char payload_data[]', ciphertext, multiline=True)
    emit_c_header_guard_end(dst_h_fp, header_ident)

    dst_h_fp.close()
    dst_c_fp.close()


if __name__ == '__main__':
    main()
