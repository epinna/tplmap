import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.jade import Jade
from basetest import BaseTest


class JadeTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'jade',
        'eval' : 'javascript' ,
        'exec' : True,
        'read' : True,
        'write' : True,
        'trailer_tag': '\n= %(trailer)s\n',
        'header_tag': '\n= %(header)s\n',
        'render_tag': '\n= %(payload)s\n',
    }

    url = 'http://127.0.0.1:15004/jade?inj=*&tpl=%s'
    plugin = Jade

    reflection_tests = [
        (1, 1, '%s', {}),
        (1, 1, 'AAA%sAAA', {}),

        (1, 1, 'a(href=\'%s\')', { 'prefix' : '1\')', 'suffix' : '//' }),
        (1, 1, 'a(href="%s")', { 'prefix' : '1")', 'suffix' : '//' }),
        (1, 1, '#container.%s', {  }),
        (1, 1, '#{%s}', { 'prefix' : '1}', 'suffix' : '//' }),

        (1, 2, '- var %s = true', { 'prefix' : 'a\n', 'suffix' : '//' }),
        (1, 1, '- var a = %s', { }),


    ]


    def test_download(self):
        pass

    def test_upload(self):
        pass
