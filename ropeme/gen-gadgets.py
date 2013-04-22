#!/usr/bin/env python
#       gen-gadgets.py
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

# generate gadgets for binary

from gadgets import *
import sys
import os

if (__name__ == "__main__"):
	g = ROPGadget(debug=0)
	try:
		binfile = sys.argv[1]
	except:
		print "Usage: " + sys.argv[0] + "binfile [depth]"
		sys.exit(-1)
	try:
		depth = int(sys.argv[2])
	except:
		depth = 3
			
	gadget_file = os.path.basename(binfile) + ".ggt"
	g.generate(binfile, backward_depth = depth)
	g.save_asm(gadget_file)
	
