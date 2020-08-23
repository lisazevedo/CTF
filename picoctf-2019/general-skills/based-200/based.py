from pwn import *
import re
import string
import binascii
# Let us see how data is stored
# falcon
# Please give the 01100110 01100001 01101100 01100011 01101111 01101110 as a word.
# ...
# you have 45 seconds.....

# Input:
HOST = '2019shell1.picoctf.com' 
PORT = 31615


def binary_data(conn):
    s = conn.recvuntil('Input:\n').decode("utf-8").split('\n')[2].split(' ')[3:-3]
    binary_data = ''.join(map(lambda x: chr(int(x, 2)), s))
    print(binary_data)
    conn.sendline(binary_data)


def oct_data(conn):
    s = conn.recvuntil('Input:\n').decode("utf-8").split('\n')[0].split('the  ')[-1].split(' as')[0].split(' ')
    oct_data = ''.join(map(lambda x: chr(int(x, 8)), s))
    print(oct_data)
    conn.sendline(oct_data)


def hex_data(conn):
    s = conn.recvuntil('Input:\n').decode("utf-8").split('\n')[0].split('the ')[-1].split(' as')[0]
    hex_data = ''.join([chr(int(''.join(c), 16)) for c in zip(s[0::2],s[1::2])])
    print(hex_data)
    conn.sendline(hex_data)


conn = remote(HOST, PORT)

binary_data(conn)
oct_data(conn)
hex_data(conn)

conn.interactive()