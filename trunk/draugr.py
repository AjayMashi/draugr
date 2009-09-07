###############################################################################
# draugr.py -- see http://www.esiea-recherche.eu/~desnos/                     #
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

import sys

from memory import Memory
from struct import unpack, pack
import re

from optparse import OptionParser
from misc import *


option_0 = { 'name' : ('-d', '--device'), 'help' : 'device : [/dev/kmem, /dev/mem, file]', 'nargs' : 1 }
option_1 = { 'name' : ('-m', '--mmap'), 'help' : 'mmap the device', 'action' : 'count' }
option_2 = { 'name' : ('-p', '--process'), 'help' : 'get processes : [ll bf(:ADDR)]', 'nargs' : 1 }
option_3 = { 'name' : ('-s', '--symbol'), 'help' : 'get a symbol : [d:NAME, s:NAME]', 'nargs' : 1 }
option_4 = { 'name' : ('-v', '--view'), 'help' : 'disasm, dump : [di:ADDR:SIZE, du:ADDR:SIZE', 'nargs' : 1 }
option_5 = { 'name' : ('-o', '--oops'), 'help' : 'dump a virtual address : [PID:ADDR:SIZE]', 'nargs' : 1 }

options = [option_0, option_1, option_2, option_3, option_4, option_5]

class TaskStruct :
    def __init__(self, offname, offpid, offuid, offtask, offrealparent, off) :
        self.offname = offname
        self.offpid = offpid
        self.offuid = offuid
        self.offgid = offuid + 16
        self.offtask = offtask
        self.offrealparent = offrealparent
        self.offmm = offtask + off + 8 

        print "OFF NAME", self.offname
        print "OFF PID", self.offpid
        print "OFF UID", self.offuid
        print "OFF GID", self.offgid
        print "OFF TASK", self.offtask
        print "OFF REAL PARENT", self.offrealparent
        print "OFF MM", self.offmm


    def State(self, buffer) :
        return unpack("<L", buffer[0:4])[0]
        
    def Name(self, buffer) :
        name = buffer[self.offname:self.offname+16]
        return name[0:name.find('\x00')]

    def Pid(self, buffer) :
        return unpack("<L", buffer[self.offpid:self.offpid+4])[0]
  
    def Uid(self, buffer) :
        return unpack("<L", buffer[self.offuid:self.offuid+4])[0]

    def Gid(self, buffer) :
        return unpack("<L", buffer[self.offgid:self.offgid+4])[0]

    def Mm(self, buffer) :
        return unpack("<L", buffer[self.offmm:self.offmm+4])[0]

    def Next(self, buffer) :
        tasknext = unpack("<L", buffer[self.offtask:self.offtask+4])[0]
        return tasknext - self.offtask
    
    def __str__(self) :
        return self.offname, self.offpid, self.offuid, self.offgid, self.offtask, self.offrealparent, self.offmm

class RealTaskStruct :
    def __init__(self, addr, m, ts, buffer, makemmap = False) :
        self.addr = addr
        self.m = m
        self.ts = ts
        self.buffer = buffer
        self.state = self.ts.State(buffer)
        self.name = self.ts.Name(buffer)
        self.pid = self.ts.Pid(buffer)
        self.uid = self.ts.Uid(buffer)
        self.gid = self.ts.Gid(buffer)
        self.mm = self.ts.Mm(buffer)
        self.next = self.ts.Next(buffer)

        if makemmap == True and self.mm > 0 :
            pgd = unpack("<L", self.m.read(self.mm + 36, 4))[0]
            print self.m.dump(self.m.pgd_to_pte(pgd), 16, 'd')

            tmp = self.m.read(self.mm, 1024)

            self.mm_mmap = unpack("<L", tmp[0:4])[0]
            #print hex(self.mm_mmap)
            while self.mm_mmap > 0 :
                vma_buf = self.m.read(self.mm_mmap, 1024)
                start = unpack("<L", vma_buf[4:8])[0]
                end = unpack("<L", vma_buf[8:12])[0]

                #print hex(start), hex(end)

                self.mm_mmap = unpack("<L", vma_buf[12:16])[0]

    def __str__(self) :
        return hex(self.addr) + " " + self.name + " PID=" + str(self.pid) + " UID=" + str(self.uid) + " GID=" + str(self.gid) + " S=" + str(self.state) + " MM=" + hex(self.mm) + " NEXT=" + hex(self.next)

class BuildTaskStruct :
    def __init__(self, m) :
        self.m = m
        self.ok = 0

    def find_offsets(self) :
        addr = self.m.symbol('init_task')
        #print "init_task 0x%x" % addr

        if addr == -1 :
            return None

        buffer = self.m.read(addr, 1024)
        #print self.m.dump(addr, 1024, 'd')
        self.offname = buffer.find("\x73\x77\x61\x70\x70\x65\x72")
        
        addrpack = pack("<L", addr)
        self.offrealparent = buffer.find(addrpack)

        #print self.m.dump(addr, 1024, 'h')
        find = 0
        for i in range(0, len(buffer), 4) :
            addr1 = unpack("<L", buffer[i:i+4])[0]
            addr2 = unpack("<L", buffer[i+4:i+8])[0]

            if addr1 != 0 and addr1 == addr2 :
                find = find + 1
                #print hex(addr1), hex(addr2), i

            if find == 2 :
                addr3 = unpack("<L", buffer[i+8:i+12])[0]
                #print hex(addr3)
                if addr3 > 0xc0000000 :
                    find = i + 16
                    break

        self.offtask = find - 8

        offstruct = 0
        for i in range(self.offtask+8, self.offrealparent, 4) :
            addr1 = unpack("<L", buffer[i:i+4])[0]
            if addr1 > 0 :
                offstruct += 4

        
        self.offpid = 44 + self.offtask + offstruct
        self.offuid = buffer[self.offrealparent+160:].find("\x00" * 32) + self.offrealparent + 160

        self.ts = TaskStruct(self.offname, self.offpid, self.offuid, self.offtask, self.offrealparent, offstruct)
        self.swapper = RealTaskStruct(addr, self.m, self.ts, buffer)
        self.ok = 1
    
class DraugrLinkedPid :
    def __init__(self, m, b) :
        self.m = m
        self.b = b

    def run(self) :
        if self.b.ok == 1 :
            print self.b.swapper
            next = self.b.swapper.next     
            while next != self.b.swapper.addr :
                buffer = self.m.read(next, 1024)

                rts = RealTaskStruct(next, self.m, self.b.ts, buffer)
                yield rts
                next = rts.next

    def runHash(self) :
        l = {}
        if self.b.ok != None :
            next = self.b.swapper.next     
            while next != self.b.swapper.addr :
                buffer = self.m.read(next, 1024)
    
                rts = RealTaskStruct(next, self.m, self.b.ts, buffer)
                l[rts.pid] = rts
                next = rts.next
        return l

class DraugrUnknownPid :
    def __init__(self, m, b, start=0xc0000000) :
        self.m = m
        self.b = b
        if start == "swapper.next" :
            self.start = self.b.swapper.next
        else :
            self.start = start
        
        self.expression = re.compile(r"([a-zA-Z0-9_\/\\\.\-\!\+\*\?#$%&\'(){},:;<=>@\[\]^|~])*\0")
        
    def run(self) :
        l = []
        nlen = 0xffffffff - self.start
        
        widgets = ['Searching @ 0x%x...: ' % self.start, Percentage(), ' ', Bar(marker=RotatingMarker())]
        pbar = ProgressBar(widgets=widgets, maxval=nlen).start()
        nbs = 0
        for j in range(self.start, 0xffffffff, 32768) :
            try :
                buff = self.m.read(j, 32768)
            except IOError, e :
                return

            m = self.expression.finditer(buff)
            for i in m :
                if i.group() != '' and i.group() != '\x00' :
                    name = i.group()
                    name = name[:name.find('\x00')]
                    if name != '' :
                        state = unpack("<L", self.m.read(j + i.start() - self.b.ts.offname, 4))[0]
                        stack = unpack("<L", self.m.read(j + i.start() - self.b.ts.offname + 4, 4))[0]
                        pid = unpack("<L", self.m.read(j + i.start() - (self.b.ts.offname - self.b.ts.offpid), 4))[0]
                        tpid = unpack("<L", self.m.read(j + i.start() - (self.b.ts.offname - self.b.ts.offpid + 4), 4))[0]
                        ptrace =  unpack("<L", self.m.read(j + i.start() - self.b.ts.offname + 16, 4))[0]

                        if (state == 1 or state == 0) and pid > 0 and pid < 65535 and tpid >= 0 and tpid < 65535 and stack >= 0xc0000000 :
                            mm = unpack("<L", self.m.read(j + i.start() - (self.b.ts.offname - self.b.ts.offmm), 4))[0]
                            activemm = unpack("<L", self.m.read(j + i.start() - (self.b.ts.offname - self.b.ts.offmm + 4), 4))[0]
                            binfmt = unpack("<L", self.m.read(j + i.start() - (self.b.ts.offname - self.b.ts.offmm + 8), 4))[0]

                            if (mm == 0 or mm >= 0xc0000000) and (activemm == 0 or activemm >= 0xc0000000) and (binfmt == 0 or binfmt >= 0xc0000000) :
                                if (mm != 0 or activemm != 0) and (mm != 0xffffffff and activemm != 0xffffffff and binfmt != 0xffffffff) :
                                    addr = j + i.start() - self.b.ts.offname
                                    buffer = self.m.read(addr, 1024)
                                    rts = RealTaskStruct(addr, self.m, self.b.ts, buffer, False)
                                    yield rts
                                    #print hex(j+i.start()-self.lpid.ts.offname), repr(name), pid, tpid, state, ptrace, hex(mm), hex(activemm), hex(binfmt)
            pbar.update(nbs)
            nbs += 32768
        pbar.finish()

class Draugr :
    def __init__(self, memory, mmap) :
        self.m = Memory(memory, "r", mmap)
        self.b = None

#        pgd = unpack("<L", self.m.read(lpid[mypid].mm + 36, 4))[0]
#        print hex(lpid[mypid].mm), hex(pgd)
#        print hex(self.m.pgd_to_pte(0xde101000)) #pgd))
#        print hex(self.m.pgd_to_pte(pgd))

    def page(self, pid, addr, size=4096) :
        if self.b == None :
            self.b = BuildTaskStruct(self.m)
            self.b.find_offsets()
        lpid = DraugrLinkedPid(self.m, self.b).runHash()
        print lpid[pid]
        pgd =  unpack("<L", self.m.read(lpid[pid].mm + 36, 4))[0]
        print hex(pgd)
        page = self.m.page(pgd, addr)
        print "PAGE @ 0x%lx" % page
        print self.m.dump(page, size, 'd')

    def lprocesses(self) :
        if self.b == None :
            self.b = BuildTaskStruct(self.m)
            self.b.find_offsets()

        lpid = DraugrLinkedPid(self.m, self.b)
        for i in lpid.run() :
            print i

    def bprocesses(self, start=0xc0000000) :
        if self.b == None :
            self.b = BuildTaskStruct(self.m)
            self.b.find_offsets()
        
        l = []
        upid = DraugrUnknownPid(self.m, self.b, start)
        for i in upid.run() :
            l.append(i)
        print

        for x in l :
            print x

    def symbol(self, name) :
        if name[0] == 'd' :
            addr = self.m.symbol(name[2:])
        elif name[0] == 'x' :
            addr = self.m.symbolXML(name[2:])
        elif name[0] == 's' :
            addr = self.m.syscall(int(name[2:]))
        else :
            raise("Ooops")

        print "%s @ 0x%lx" % (name[2:], addr)

    def disasm(self, addr, size) :
        for i in self.m.disasm(addr, size) :
            print "0x%08x (%02x) %-20s %s" % (i.offset, i.size, i.instructionHex, str(i.mnemonic) + " " + str(i.operands))

    def dump(self, addr, size) :
        print self.m.dump(addr, size, 'h')

def main(options, arguments) :
    device = "/dev/kmem"
    mmap = False

    if options.device != None :
        device = options.device

    if options.mmap != None :
        mmap = True

    d = Draugr(device, mmap)

    if options.process != None :
        if options.process[:2] == "ll" :
            d.lprocesses()
        elif options.process[:2] == "bf" :
            if len(options.process) > 2 :
                start = options.process.split(":")[1]
                if start == "swapper.next" :
                    d.bprocesses(start)
                else :
                    d.bprocesses(int(start, 16))
            else :
                d.bprocesses()

    elif options.symbol != None :
        d.symbol(options.symbol)

    elif options.view != None :
        l = options.view.split(":")
        if l[0] == "di" :
            d.disasm(int(l[1], 16), int(l[2]))
        elif l[0] == "du" :
            d.dump(int(l[1], 16), int(l[2]))
    elif options.oops != None :
        l = options.oops.split(":")
        d.page(int(l[0]), int(l[1], 16), int(l[2]))


if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)
