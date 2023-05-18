#!/usr/bin/env python3

text_str = "Hello, World!"
print(text_str)

text_str_to_hex = text_str.encode("utf-8").hex()
print(text_str_to_hex)

hex_to_text_str = bytes.fromhex(text_str_to_hex).decode("utf-8")
print(hex_to_text_str)

text_str_to_bin = " ".join(format(ord(i), "08b") for i in text_str)
print(text_str_to_bin)

text_bin_without_spaces = "".join(text_str_to_bin.split())
print(text_bin_without_spaces)

bin_to_text_str = "".join(chr(int(text_bin_without_spaces[i:i+8], 2)) for i in range(0, len(text_bin_without_spaces), 8))
print(bin_to_text_str)

bin_to_utf8_text_str = bytearray([int(text_bin_without_spaces[i:i+8], 2) for i in range(0, len(text_bin_without_spaces), 8)])
print(bin_to_utf8_text_str.decode("utf-8"))