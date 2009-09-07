###############################################################################
# memory.py -- see http://www.esiea-recherche.eu/~desnos/                     #
#                                                                             #
# 2009 : desnos@nospam.esiea.fr                                               #
# This program is free software;                                              #
# you can redistribute it and/or modify it under the terms of the GNU         #
# General Public License as published by the Free Software Foundation;        #
# Version 2. This guarantees your right to use, modify, and                   #
# redistribute this software under certain conditions.                        #
#                                                                             #
# Source is provided to this software because we believe users have a         #
# right to know exactly what a program is going to do before they run         #
# it.                                                                         #
#                                                                             #
# This program is distributed in the hope that it will be                     #
# useful, but WITHOUT ANY WARRANTY; without even the implied                  #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR                     #
# PURPOSE. See the GNU General Public License for more details (              #
# http://www.gnu.org/copyleft/gpl.html ).                                     #
#                                                                             #
###############################################################################

import sys, os, string, mmap, atexit, xml.dom.minidom
from struct import unpack, pack
from functools import wraps
from pydistorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits

from ctypes.util import find_library
from ctypes import (cdll, Structure, Union, sizeof, addressof, create_string_buffer, c_char, c_ushort, c_int, c_uint, c_char_p, c_ulong, c_void_p)

class IDTR(Structure):
    _fields_ = [
        ("limit", c_ushort),
        ("base", c_ulong)
        ]

class MemoryBase(object) :
    def open(self, mode, typeaccess):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError
    
    def read(self, pos, len):
        raise NotImplementedError

    def write(self, pos, buf):
        raise NotImplementedError

    def symbol(self, name) :
        raise NotImplementedError

    def get_addr(self, pos) :
        return pos

    def set_addr(self, pos) :
        return pos

    def reverseOpcodes(self, opcodes) :
        temp = ""
        i = 0
        
        for i in range(0, len(opcodes) , 2) :
            temp = opcodes[i:i+2] + temp
        temp = temp[:8]
        temp = temp.replace(' ', '0')
        return temp

    # TODO : simplify this code
    def debugdump(self, addr, length) :
        tabtrans = "................................ !\"#$%&'()*+,-./0123456789:" \
                   ";<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu" \
                   "vwxyz{|}~..................................................." \
                   "............................................................" \
                   ".................."

        globalop = "\n"
        op = ""
        ascii = ""
        for i in range(0, length, 4) :
            data = self.read(addr + i, 4)
            temp = '%8x' % unpack("<L", data)[0]
            tmp = self.reverseOpcodes(temp)
            for j in range(0, len(tmp), 2) :
                ascii = ascii + tabtrans[int(tmp[j:j+2], 16)]
                op = op + tmp[j:j+2] + ' '

            if(i > 0 and (i+4) % 8 == 0) :
                op = op + ' '
            if(i > 0 and (i+4) % 16 == 0) :
                op = op + '|'
                ascii = ' ' + ascii + '\n'

                globalop = globalop + op + ascii
                ascii = ""
            else :
                globalop = globalop + op

            op = ""

        return globalop

        
    def hexdump(self, addr, length) :
        var = ""
        for i in range(0, length, 4) :
            data = self.read(addr + i, 4)
            temp = '%8x' % unpack("<L", data)[0]
            if(i % 16 == 0):
                var = var + '\n%8x+%.8d : ' % (addr, i)

            var = var + self.reverseOpcodes(temp) + ' '

        return var

    def opcodedump(self, addr, length) :
        op = "\n\""
        for i in range(0, length, 4) :
            data = self.read(addr + i, 4)
            temp = '%8x' % unpack("<L", data)[0]
            tmp = self.reverseOpcodes(temp)
            for j in range(0, len(tmp), 2):
                op = op + '\\x' + tmp[j:j+2]

            if(i > 0 and (i+4) % 8 == 0) :
                op = op + '"\n"'

        if(op[len(op) - 1] == "\"") :
            op = op[:-2]
        else :
            op = op + '"'
        
        return op

    def dump(self, addr, length, dtype):
        if(dtype == 'd') :
            return self.debugdump(addr, length)
        elif(dtype == 'h') :
            return self.hexdump(addr, length)
        elif(dtype == 'o') :
            return self.opcodedump(addr, length)

    def disasm(self, addr, length) :
        searchret = False
        if length == -1 :
            length = 1000
            searchret = True

        raw = self.read(addr, length)
        for i in Decode(addr, raw, Decode32Bits):
            yield i
            if searchret == True :
                if str(i.mnemonic) == "RET" :
                    return

    def writeOpcodes(self, addr, chaine) :
        chaine = chaine.replace("\"", '')
        chaine = chaine.replace("\'", '')
        
        liste = string.split(chaine, '\\x')
        opco = ""
        for i in liste :
            tmp = string.replace(i, '\\x', '')

            if(tmp != "") :
                valint = int(tmp, 16)
                opco += pack('B', valint)
                
        self.write(addr, opco)

    def find(self, name, off=0xc0000000) :
        if self.typeaccess == False :
            tmpname = name[:-1]
            i = off 
            while i < 0xc1000000 : 
                buf = self.read(i, len(tmpname))
                if buf == tmpname :
                    return i

                i = i + 1
            return -1

        self.data.seek(self.get_addr(off), 0)
        return self.set_addr(self.data.find(name))

    def ksymtab(self, addr) :
        if addr <= 0 :
            return -1

        maxlen = 0x40000
        addrpack = pack("<L", addr)
       
        off = addr - maxlen
        off = off - off % 4
        valmax = 0xc0000000 + 0x1000000

        for i in range(off, valmax, 4) :
            if self.read(i, 4) == addrpack :
                newaddr = i - 4
                return unpack("<L", self.read(newaddr, 4))[0]

        return -1

    def cache(f) :
        f.cache = {}
        @wraps(f)
        def cache_func(*args) :
            if args in f.cache :
                return f.cache[args]

            f.cache[args] = res = f(*args)
            return res
        return cache_func

    @cache
    def symbol(self, name) :  
        name = name + '\0'

        off = 0xc0000000
        while 1 :
            addr = self.find(name, off)
            if addr == -1 :
                return -1

            naddr = self.ksymtab(addr)
            if naddr != -1 :
                return naddr

            off = addr + 1

    def symbolXML(self, name) :
        fd = open(name, "r")
        l = fd.readlines()
        fd.close()
        
        bufxml = ""
        for i in l :
            bufxml += i

        document = xml.dom.minidom.parseString(bufxml)

        addr = -1
        for item in document.getElementsByTagName('start') :
            for i in item.getElementsByTagName('next') :
                next = i.getAttribute('name')
                name = i.getElementsByTagName('name').item(0).firstChild.data
                value = i.getElementsByTagName('value').item(0).firstChild.data
                print next, name, value, "==>",
                if next == "syscall" :
                    addr = self.syscall(int(value))
                else :
                    addr = self.findMnemonic(addr, next, int(value))
                
                print hex(addr)

        return addr

    def findMnemonic(self, addr, name, value) :
        index = -1
        l = []
        for i in self.disasm(addr, -1) :
            #print "0x%08x (%02x) %-20s %s" % (i.offset, i.size, i.instructionHex, str(i.mnemonic) + " " + str(i.operands))
            if value == -1 :
                if str(i.mnemonic) == name.upper() :
                    l.append([str(i.mnemonic), str(i.operands)])
            else :
                if str(i.mnemonic) == name.upper() :
                    index = index + 1

                if index == value :
                    return int(str(i.operands), 16)
    
        if value == -1 :
            return int(l[len(l) - 1][1], 16)

        return -1

    def idt(self, pos) :
        idtlib = cdll.LoadLibrary("./idt.so")

        i1 = IDTR()
        idtlib.draugr_idt(addressof(i1))
        
        buff = self.read(i1.base + 8 * pos, 8)
        addr = (unpack("<H", buff[6:8])[0] << 16) | unpack("<H", buff[0:2])[0]
        return addr
        
    def syscall(self, pos) :
        idtlib = cdll.LoadLibrary("./idt.so")

        i1 = IDTR()
        idtlib.draugr_idt(addressof(i1))
#        print hex(i1.base), hex(i1.limit)

        if i1.base < 0xc0000000 or i1.base > 0xd0000000 :
            addr = self.find("\x66\xf7\x45\x08")
            addr = self.find("\xff\x14\x85", addr)
            buff = self.read(addr, 64)
            off = 0
        else :
            buff = self.read(i1.base + 8 * 0x80, 8)
            system_call = (unpack("<H", buff[6:8])[0] << 16) | unpack("<H", buff[0:2])[0]
#        print hex(system_call)

            buff = self.read(system_call, 255)
            off = buff.find("\xff\x14\x85")
        
        sys_call_table = unpack("<L", buff[off+3:off+3+4])[0]

#        print hex(sys_call_table)

        addr = unpack("<L", self.read(sys_call_table + 4 * pos, 4))[0]
        return addr

class Kmem(MemoryBase) :    
    def open(self, mode, typeaccess = False) :
        self.typeaccess = typeaccess
        try :
            self.fd = open("/dev/kmem", mode)
        except IOError, e :
            raise(e)

        if(self.typeaccess == True) :
            raise("mmap is not implemented on device /dev/kmem")

    def close(self) :
        self.fd.close()

    def read(self, addr, length, ttype = True) :
        try :
            self.fd.seek(addr, 0)
            temp = self.fd.read(length)
        except IOError, e :
            raise(e)

        return temp

    def write(self, addr, buf) :
        try :
            self.fd.seek(addr, 0)
            self.fd.write(buf)
        except IOError, e :
            raise(e)

class Mem(MemoryBase) :
    def get_addr(self, pos) :
        addr = 0
        if((pos & 0xffffffffff000000) == 0xffffffff80000000) :
            addr = pos & 0x0000000000ffffff
        elif((pos & 0xffffff0000000000) == 0xffff810000000000) :
            addr = pos & 0x000000ffffffffff
        else :
            addr = pos - 0xc0000000
        return addr

    def set_addr(self, pos) :
        if pos > 0 :
            addr = pos + 0xc0000000
            return addr
        return pos

    def open(self, mode, typeaccess = False, mmapmode = mmap.MAP_PRIVATE) :
        self.typeaccess = typeaccess
        try :
            self.fd = open("/dev/mem", mode)
        except IOError, e :
            raise(e)

        if self.typeaccess == True:
            try :
                if(mode == 'w' or mode == 'a+') :
                    mmapmode = mmap.MAP_SHARED
                # TODO : FIX RAM LENGTH
                self.data = mmap.mmap(self.fd.fileno(), 100 * 1024 * 1024, mmapmode)
                self.maxaddr = 0xc0000000 + len(self.data)
            except TypeError, e :
                raise(e)

    def close(self) :
        self.fd.close()
        if self.typeaccess == True:
            self.data.close()

    def read(self, addr, length, ttype = True) :
        if self.typeaccess == True :
            if addr+length > self.maxaddr :
                ttype = False

        if ttype == False :
            realtype = ttype
        else :
            realtype = self.typeaccess
        
        try :
            if(realtype == False) :
                self.fd.seek(self.get_addr(addr), 0)
                return self.fd.read(length)
            else :
                self.data.seek(self.get_addr(addr), 0)
                return self.data.read(length)
        
        except ValueError,e :
            raise(e)

        return 0

    def write(self, addr, buf, ttype = True) :
        if ttype == False :
            realtype = ttype
        else:
            realtype = self.typeaccess

        if(realtype == False) :
            self.fd.seek(self.get_addr(addr), 0)
            self.fd.write(buf)
        else :
            self.data.seek(self.get_addr(addr), 0)
            self.data.write(buf)

class MemFile(Mem) :
    def __init__(self, path) :
        self.path = path

    def open(self, flags, typeaccess = False) :
        self.fd = open(self.path, flags)
        self.data = self.fd.read()
        self.typeaccess = False

    def read(self, addr, length, ttype=1) :
        val = self.get_addr(addr)
        return self.data[val:val + length]

    def write(self, addr, buf) :
        raise NotImplementedError

    def close(self) :
        self.fd.close()

class Memory :
    def __init__(self, name, flags, memorymmap = False) :
        self.mem = None
        self.name  = name
        self.flags = flags

        if self.name == "/dev/kmem" :
            self.mem = Kmem()
        elif self.name == "/dev/mem" :
            self.mem = Mem()
        else :
            self.mem = MemFile(name)

        if self.mem == None :
            raise("Unknown memory")

        print "OPEN ", self.name, "with mmap =", memorymmap
        self.mem.open(flags, memorymmap)
        atexit.register(self.close)

    def read(self, addr, length) :
        return self.mem.read(addr, length)

    def write(self, addr, buf) :
        return self.mem.write(addr, buf)

    def find(self, name, off=0xc0000000) :
        return self.mem.find(name, off)

    def symbol(self, name) :
        return self.mem.symbol(name)

    def symbolXML(self, name) :
        return self.mem.symbolXML(name)

    def idt(self, pos) :
        return self.mem.idt(pos)

    def page(self, mmpgd, addr) :

#define pgd_offset(mm, address) ((mm)->pgd + pgd_index((address)))
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#/*
# * traditional i386 two-level paging structure:
# */
#define PGDIR_SHIFT     22
#define PTRS_PER_PGD    1024
#/*
# * PGDIR_SHIFT determines what a top-level page table entry can map
# */
#define PGDIR_SHIFT     30
#define PTRS_PER_PGD    4
        tmp = addr

        #print hex(mmpgd)
        pgd = mmpgd + ((tmp >> 22) & (1024 - 1)) * 4
        #print hex(pgd)

#define PTRS_PER_PTE 1024 
#define PAGE_SHIFT	12
#define PAGE_MASK	(~(PAGE_SIZE-1))

#define PTE_PFN_MASK		((pteval_t)PHYSICAL_PAGE_MASK)
#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define __PHYSICAL_MASK		((phys_addr_t)(1ULL << __PHYSICAL_MASK_SHIFT) - 1)

#PAE ==>
#define __PHYSICAL_MASK_SHIFT   64
#!PAE ==> 
#define __PHYSICAL_MASK_SHIFT   32

   #define pte_index(address)                                      \
#        (((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define pmd_val(x)	native_pmd_val(x)
#static inline pmdval_t native_pmd_val(pmd_t pmd)
#{
#        return pmd.pmd;
#}

#static inline pmdval_t native_pmd_val(pmd_t pmd)
#{
#        return native_pgd_val(pmd.pud.pgd);
#}

#define pmd_page_vaddr(pmd)                                     \
#        ((unsigned long)__va(pmd_val((pmd)) & PTE_PFN_MASK))

#define pte_offset_kernel(dir, address)                         \
#        ((pte_t *)pmd_page_vaddr(*(dir)) +  pte_index((address)))

        
        PTE_PFN_MASK = 0xfffff000

        dirp = unpack("<L", self.read(pgd, 4))[0]#0x1e1f6067 #(*pgd)
        #print hex(dirp)
        off1 = (dirp + 0xc0000000) & PTE_PFN_MASK
        off2 = (tmp >> 12) & (1024 - 1)

        pte = off1 + off2 * 4
        #print hex(off1), hex(off2)
        #print hex(pte)
#define pte_page(pte)	pfn_to_page(pte_pfn(pte))
#static inline unsigned long pte_pfn(pte_t pte)
#{
#        return (pte_val(pte) & PTE_PFN_MASK) >> PAGE_SHIFT;
#}
#define pte_val(x)	native_pte_val(x)
#static inline pteval_t native_pte_val(pte_t pte)
#{
#        return pte.pte;
#}

#define pfn_to_page __pfn_to_page
#define __pfn_to_page(pfn)      (mem_map + ((pfn) - ARCH_PFN_OFFSET))
#define ARCH_PFN_OFFSET         (0UL)

        pte = unpack("<L", self.read(pte, 4))[0] #0x1d6bd025#*pte
        pte = (pte & PTE_PFN_MASK) >> 12
        #print hex(pte)

        mem_map = 0xc1000000
        page_addr = mem_map + pte * 0x20 #(sizeof(page))
        
        #print hex(page_addr)
# __va(page_to_pfn(page_at_addr) << PAGE_SHIFT));
#define page_to_pfn __page_to_pfn
#define __page_to_pfn(page)     ((unsigned long)((page) - mem_map) + ARCH_PFN_OFFSET)

        
        ptp = (page_addr - mem_map)/0x20
        #print hex(ptp)
        page = 0xc0000000 + ((ptp + 0) << 12)
        #print self.dump(page, 16, 'd')
        return page

    def dump(self, addr, length, mode) :
        return self.mem.dump(addr, length, mode)

    def disasm(self, addr, length) :
        return self.mem.disasm(addr, length)

    def syscall(self, num) :
        return self.mem.syscall(num)

    def close(self) :
        return self.mem.close()
