import cmd

class Shell(cmd.Cmd):
    """Interactive shell."""
    
    def __init__(self, inject_function, prompt):
        cmd.Cmd.__init__(self)
        
        self.inject_function = inject_function
        self.prompt = prompt
    
    def default(self, line):
        print self.inject_function(line)
    
    def emptyline(self):
        pass
        
class MultilineShell(cmd.Cmd):
    """Interactive multiline shell."""
    
    def __init__(self, inject_function, prompt):
        cmd.Cmd.__init__(self)
        
        self.inject_function = inject_function
        self.fixed_prompt = prompt
        
        self.lines = []
        
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

    def do_EOF(self, line):
        # Run the inject function and reset the state
    
        # Send the current line as well
        if line:
            self.lines.append(line)

        print
        print self.inject_function('\n'.join(self.lines))
        self.lines = []
        
    
        