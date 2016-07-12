from core.check import Check
from utils.loggers import log
from utils import rand

class Twig(Check):

    render_tag = '{{%(payload)s}}'
    header_tag = '{{%(header)s}}'
    trailer_tag = '{{%(trailer)s}}'
    contexts = [
        { 'level': 1, 'prefix': '""%(closure)s}}', 'suffix' : '{{""' },
    ]

    def detect_engine(self):

        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        # {{7*'7'}} and a{#b#}c work in freemarker as well
        payload = '{%% set a=%i*%i %%}{{a}}' % (randA, randB)
        expected = str(randA * randB)

        if expected == self.inject(payload):
            self.set('language', 'php')
            self.set('engine', 'twig')
