ROPEME - ROP Exploit Made Easy

Proof-Of-Concept Return-Oriented-Programming automation tool
Version: Black Hat USA 2010 - Jul 28, 2010

Copyright (c) 2010 by Long Le Dinh <longld at vnsecurity.net>

This file has been released under the GNU GPL version 2 or later.

ROPME is a set of python scripts to generate ROP gadgets and payload.


Requirements
------------
- Python >=2.6
- diStorm64 - for disassembly
- binutils

Usages
------
- ropshell.py: interactive ROP shell to generate and search for gadgets

$ ropeme/ropshell.py 
Simple ROP interactive shell: [generate, load, search] gadgets
ROPeMe> help
Available commands: type help <command> for detail
  generate  	Generate ROP gadgets for binary 
  load      	Load ROP gadgets from file 
  search    	Search ROP gadgets 
  shell     	Run external shell commands 
  ^D        	Exit

ROPeMe> 
**

- ropsearch.py: search for ADD MEM gadgets sequence in binary

$ ropeme/ropsearch.py vuln 4
Searching ROP sequences for binary: vuln
Generating gadgets for vuln with backward depth=4
It may take few minutes depends on the depth and file size...
Processing code block 1/1
Generated 87 gadgets
Found ROP sequences for file vuln:
### start ###
# pop ecx ; pop ebx ; leave ;; = 0x8048624
# pop ebp ;; = 0x80484b4
# add [ebp+0x5b042464] ecx ; pop ebp ;; = 0x80484ae
### end ###
Warning: trailing "leave" found in ROP sequence: [('pop ecx ; pop ebx ; leave ;;', 134514212L), ('pop ebp ;;', 134513844L), ('add [ebp+0x5b042464] ecx ; pop ebp ;;', 134513838L)]
**

- payload.py: sample ROP stage-1 and stage-0 payload generator. See the sample exploit.py for usage.
