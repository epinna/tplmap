import cmd

class Shell(cmd.Cmd):
    """Interactive shell."""
    
    def __init__(self, inject_function, prompt):
        cmd.Cmd.__init__(self)
        
        self.inject_function = inject_function
        self.prompt = prompt
    
    def default(self, line):
        print self.inject_function(line)
        
        
class MultilineShell(cmd.Cmd):
    """Interactive multiline shell."""
    
    def __init__(self, inject_function, prompt):
        cmd.Cmd.__init__(self)
        
        self.inject_function = inject_function
        self.fixed_prompt = prompt
        
        self.lines = []
        self.empty_lines = 0
        
        self._format_prompt()

    def _format_prompt(self):
        self.prompt = '[%i] %s' % (
                len(self.lines), 
                self.fixed_prompt
        )

    def postcmd(self, stop, line):
        self._format_prompt()
        return stop

    def default(self, line):
        self.lines.append(line)
        
    def emptyline(self):
        
        # Do not save empty line if there is nothing to send
        if not self.lines:
            return
        
        # Else, increase the empty lines amount. If two, run
        # the inject function and reset the state
        self.empty_lines += 1
        if self.empty_lines == 2:
            print self.inject_function('\n'.join(self.lines))
            self.lines = []
            self.empty_lines = 0
        
    
        