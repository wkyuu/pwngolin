#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# paste from self-used pwn-libs.
from pwn import *
from LibcSearcher import LibcSearcher

context(log_level = 'debug', arch = 'amd64', os = 'linux')

# change sth is up to you.
filename = ''
libc_path = ''
remote_ip = ''
remote_port = ''

io = pwnlib.process(filename)
# io = pwnlib.remote(remote_ip, remote_port)

elf = pwnlib.ELF(filename)

send            = lambda payload            :io.send(str(payload))
sendline        = lambda payload            :io.sendline(str(payload))
sendafter       = lambda recv, payload      :io.sendafter(str(recv), str(payload))
sendlineafter   = lambda recv, payload      :io.sendlineafter(str(recv), str(payload))

recv            = lambda msg                :io.recv(msg)
recvuntil       = lambda msg, drop = True   :io.recvuntil(msg, drop)

leak            = lambda sth, addr          :log.success('{} => {:#x}'.format(sth, addr))
u32             = lambda bytes              :pwnlib.u32(bytes.ljust(4, '\0'))
u64             = lambda bytes              :pwnlib.u64(bytes.ljust(8, '\0'))

interactive     = lambda                    :io.interactive()

def dbg():
    gdb.attach(io)
    pause()

def ret2libc(leak, func, libc_path = ''):
	if libc_path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(libc_path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)