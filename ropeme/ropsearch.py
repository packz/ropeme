#!/usr/bin/env python
#       ropsearch.py
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

# Search binary for LOAD/STORE gadgets to build ROP exploit:
# pop r1
# pop r2
# add [r1 + 0xbabeface], r2
# Give warning if there is a trailing "leave" instruction

from gadgets import *
import sys

REGISTERS_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
REGISTERS_16 = ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']

# search for pop gadgets
# flag = 0: no trailing instruction after gadget
def search_pop(gadget, reg = '', flag = 0):
    reg = reg.replace("h", "x").replace("l", "x").replace("e", "")
    reg = "e" + reg
    search = "pop "
    if reg == '': # search for all pop gadgets
        search += "?"
    else:
        search += reg

    result = gadget.asm_search(search)
    if result == [] and flag != 0: # try to search all if flag = 1
        search += " %"
        result = gadget.asm_search(search, [set(["-leave"]), set([])]) # try no trailing leave
        if result == []:
            result = gadget.asm_search(search)
    
    return result
    
# search for add [mem], reg gadgets
# flag = 0: no trailing instruction after gadget
def search_add_mem(gadget, reg1 = '', reg2 = '', flag = 0):
    search_1 = "add [ "
    search_2 = search_1
    if reg1 == '': # search for all add gadgets
        search_1 += "? ] "
        search_2 += "? ? ? ] "
    else:
        search_1 += reg1 + " ] " 
        search_2 += reg1 + " ? ? ] " 

    if reg2 == '': # search for all add gadgets
        search_1 += "?"
        search_2 += "?"
    else:
        search_1 += reg2
        search_2 += reg2

    result = gadget.asm_search(search_1, [set(["-leave"]), set([])])
    if result == []:
        result = gadget.asm_search(search_2, [set(["-leave"]), set([])])
        search = search_2
    else:
        search = search_1
    if result == [] and flag != 0: # try to search all if flag = 1
        search += " %"
        result = gadget.asm_search(search, [set(["-leave"]), set([])]) # try no trailing leave
        if result == []:
            result = gadget.asm_search(search)
            #print result
    
    return result

# search for the sequence gadgets
# pop r1
# pop r2
# add [r2 + 0xbabeface], r1
# flag = 0: no trailing instruction after gadget
def search_gadget_addmem(gadget, flag = 0):
    result = []
    for r1 in REGISTERS_32:
        for r2 in REGISTERS_32:
            if r1 == r2: continue
            res = search_add_mem(gadget, r1, r2, flag)
            if res != []: # found an add, now search back for pop
                res1 = search_pop(gadget, r1, flag)
                if res1 != []: 
                    res2 = search_pop(gadget, r2, flag)
                    if res2 != []: # sequence found
                        result += [[res2[0]] + [res1[0]] + [res[0]]]

    return result

# check ROP sequence for file
def checkfile(filename, depth = 1, verbose = 0):
    if verbose != 0:
        print >>sys.stderr, "Searching ROP sequences for binary:", filename
        
    gadget = ROPGadget(debug=0)
    gadget.generate(filename, backward_depth = depth)
    if depth > 1:
        flag = 1
    else:
        flag = 0
        
    result = search_gadget_addmem(gadget, flag)
    
    if verbose != 0:
        if result != []:
            print >>sys.stderr, "Found ROP sequences for file %s:" % filename
            for sequence in result:
                print >>sys.stderr, "### start ###"
                for (code, offset) in sequence:
                    print >>sys.stderr, "# %s = 0x%x" % (code, offset)
                print >>sys.stderr, "### end ###"
            for sequence in result:
                if " ".join([str(s) for s in sequence]).find("leave") != -1:
                    print >>sys.stderr, "Warning: trailing \"leave\" found in ROP sequence:", sequence
                    break
        else:
            print >>sys.stderr, "Could not find ROP sequences for file %s" % filename
            
    return result

if (__name__ == "__main__"):
    try:
        filename = sys.argv[1]
    except:
        print "Usage: %s <filepath> [depth]" % sys.argv[0] 
    
    depth = 3
    try:
        depth = int(sys.argv[2])
    except:
        pass

    checkfile(filename, depth, verbose=1)
