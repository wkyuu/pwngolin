# -*- coding: utf-8 -*-

from pwn import *

funclist = [
    ['system', 'plt'], 
    ['system', 'got'], 
    ['puts', 'plt'], 
    ['puts', 'got'], 
    ['write', 'plt'], 
    ['write', 'got'], 
    ['str_binsh', 'string'], 
    ['ret', 'asm'],
    ]

def getFile():
    try:
        elfname = sys.argv[1]
    except BaseException:
        banner = '''
    输入 elfname
    example: python addr.py libc.so.6
        '''
        print(banner)
        exit()
    return elfname

def check(elfname):    
    elf = ELF(elfname)
    for func in funclist:
        funcion(elf, func[0], func[1]).start()
    
class funcion():
    def __init__(self, elf, name, mode):
        self.elf = elf
        self.name = name
        self.mode = mode
        
    def start(self):
    
        def plt(self):
            try:
                plt = hex(self.elf.plt[self.name])
                print(self.name, '=> ', plt)
            except BaseException:
                print(self.name, '=> ', None)
                
        def got(self):
            try:
                got = hex(self.elf.got[self.name])
                print(self.name, '=> ', got)
            except BaseException:
                print(self.name, '=> ', None)

        def string(self):
            try:
                str_bin_sh = hex(next(self.elf.search(b"/bin/sh")))
                print(self.name, '=> ', str_bin_sh)
            except BaseException:
                print(self.name, '=> ', None)
                
        def myAsm(self):
            try:
                ret_addr = hex(next(self.elf.search(b'\xc3')))
                print(self.name, '=> ', ret_addr)
            except BaseException:
                print(self.name, '=> ', None)
        
        case = {
            'plt': plt,
            'got': got,
            'string': string,
            'asm': myAsm
        }

        if self.mode in case.keys():
            case.get(self.mode)(self)
    
if __name__ == "__main__":
    elfname = getFile()
    try:
        check(elfname)
    except Exception as e:
        print(e)
    