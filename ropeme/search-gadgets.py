#!/usr/bin/env python
#       search-gadgets.py
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

from gadgets import *
import sys
import os

# search gadgets database

if (__name__ == "__main__"):
	g = ROPGadget(debug=0)
	try:
		gadget_file = sys.argv[1]
	except:
		print "Usage: " + sys.argv[0] + " gadget_file asm_code"
		sys.exit(-1)
	g.load_asm(gadget_file)
	
	try:
		code = sys.argv[2]
	except:
		code = "*"
	for result in g.asm_search(code):
		if len(result) > 1:
			(code, offset) = result
			print hex(offset), ":", code
	
