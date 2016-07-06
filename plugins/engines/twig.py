from core.check import Check
from utils.loggers import log
from utils import rand
import string
import requests
import urlparse
import os


class Twig(Check):

    render_tag = '{{%(payload)s}}'
    header_tag = '{{%(header)s}}'
    trailer_tag = '{{%(trailer)s}}'
    contexts = [
        { 'level': 1, 'prefix': '""}}', 'suffix' : '{{""' },
    ]

    def detect_engine(self):

        randA = rand.randint_n(1)

        payload = '{{7*\'%s\'}}' % (randA)
        expected = str(randA*7)

        if expected == self.inject(payload):
            self.set('language', 'python')
            self.set('engine', 'twig')
