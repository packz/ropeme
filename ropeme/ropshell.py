#!/usr/bin/env python2
#       ropshell.py
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

import cmd
import os
import sys
import gadgets

# Simple ROP interactive shell
class ROPShell(cmd.Cmd):
    """Simple ROP shell """
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "\033[1;31mROPeMe> \033[0m"
        self.intro = "Simple ROP interactive shell: [generate, load, search] gadgets"
        self.ruler = '-'
        self.__gadgets = gadgets.ROPGadget(debug=0)

    # generate gadgets for binary
    def do_g(self, line):
        self.do_generate(line)
        
    def do_generate(self, line):
        """Generate ROP gadgets for binary """
        if line == "":
            self.help_generate()
            return ''
            
        line = line.split()
        file_in = line[0]
        file_out = os.path.basename(file_in) + ".ggt"
        try:
            depth = int(line[1])
        except:
            depth = 3
        
        try:
            open(file_in, 'r')
        except:             
            print "Cannot access " + file_in
            return ''
        
        if self.__gadgets.info()["hash"] != "": # remove the old gadget
            del self.__gadgets
            self.__gadgets = gadgets.ROPGadget()
            
        self.__gadgets.generate(file_in, depth)
        self.__gadgets.save_asm(file_out)           
        print "OK"
        return ''
        
    def help_generate(self):
        print '\n'.join([ 'Generate ROP gadgets for binary with custom backward search depth,',
                            'the result will be saved to file binary.ggt',
                            'Usage: generate binary [depth]',
                            'Example: generate /lib/libc.so.6 4',
                       ])

    # load gadgets from file
    def do_l(self, line):
        self.do_load(line)
        
    def do_load(self, line):
        """Load ROP gadgets from file """
        if line == "":
            self.help_load()
            return ''
            
        line = line.split()
        gadget_file = line[0]

        try:
            open(gadget_file, 'r')
        except:             
            print "Cannot access " + gadget_file
            return ''
        
        self.__gadgets.load_asm(gadget_file)
        print "OK"
        return ''
        
    def help_load(self):
        print '\n'.join([ 'Load ROP gadgets from gadget_file',
                            'Usage: load gadget_file',
                            'Example: load libc.ggt',
                       ])

    # search gadgets
    def do_s(self, line):
        self.do_search(line)
        
    def do_search(self, line):
        """Search ROP gadgets """
        if line == "":
            self.help_search()
            return ''
        
        if self.__gadgets.info()["hash"] == "":
            print "Gadgets are not loaded"
            return ''
        
        search_code = ""    
        constraints = []
        lines = line.strip().split()
        for s in lines:
            if s[0] == "-" and len(s) > 1: # a constraint
                constraints += [s]
            else:
                search_code += " " + s
            
        print "Searching for ROP gadget: " + search_code + " with constraints:", constraints
        
        output = ""
        for result in self.__gadgets.asm_search(search_code, [set(constraints), set([])]):
            if len(result) > 1:
                (code, offset) = result
                # just list out unique code for 3 times
                output += hex(offset) + ": " + code + "\n"
        keywords = search_code.replace("?", "").replace("%", "").replace("[", "").replace("]", "").strip()
        keywords = keywords.split()
        self.__page(output, keywords)
        
        return ''
        
    def help_search(self):
        print '\n'.join([ 'Search for ROP gadgets, support wildcard matching ?, %',
                            'Usage: search gadget [-exclude_instruction]',
                            'Example: search mov eax ? # search for all gadgets contains "mov eax"',
                            'Example: search add [ eax % ] % # search for all gadgets starting with "add [eax"', 
                            'Example: search pop eax % -leave # search for all gadgets starting with "pop eax" and not contain "leave"',
                       ])

    # run external shell commands
    def do_shell(self, line):
        """Run external shell commands """
        output = os.popen(line).read()
        self.__page(output)

    def help_shell(self):
        print '\n'.join([ 'Run external shell commands',
                            'Usage: ! cmd or shell cmd',
                            'Example: ! ls',
                       ])
                
    # precmd processing
    def precmd(self, line):
        if line.strip() == 'help':
            self.do_help(line)
            return ''
        
        cmd, arg, line = self.parseline(line)
        if arg == '?':
            cmds = self.completenames(cmd)
            if len(cmds) > 1:
                print "Possible commands:"
                self.columnize(cmds)
                print ""
            return cmd

        return line
            
    def emptyline(self):
        return ''
        
    # generic help function
    def do_help(self, line):
        cmd, arg, line = self.parseline(line)
        #print self.parseline(line)
        if cmd != None and cmd != "help":
            cmds = self.completenames(cmd)
            if len(cmds) == 1:
                getattr(self, "help_" + cmds[0])()
                return ''
            
        print '\n'.join([ 'Available commands: type help <command> for detail',
                       ])
        doc_strings = [ (i[3:], getattr(self, i).__doc__) for i in dir(self) if i.startswith('do_') ]
        doc_strings = [ '  %s\t%s\n' % (i.ljust(10, " "), j) for i, j in doc_strings if j is not None ]
        doc_strings += [ '  %s\t%s\n' % ("^D".ljust(10), "Exit")]
        print ''.join(doc_strings)

    def do_EOF(self, line):
        return True

    # simple paging
    def __page(self, str, keywords=[], lines=25):
        for k in keywords:
            str = str.replace(k, self.__highlight(k))
        text = str.split('\n')
        length = len(text)
        for linenum in range(length):
            print text[linenum]
            if linenum % lines == 0 and linenum >= lines:
                key = raw_input('--More-- (%d/%d)' % (linenum-1, length))
                if key == 'q': 
                    break

    # linux ansicolor highlighting
    def __highlight(self, word, color = "green"):
        output = ""
        suffix = "\033[0m"
        if color == "green":
            prefix = "\033[1;32m"
        
        output = prefix + word + suffix
        return output


#   def postloop(self):
#       pass
                
if __name__ == '__main__':
    ROPShell().cmdloop()
        
        
