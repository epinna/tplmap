import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.pug import Pug
from basetest import BaseTest


class PugTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'pug',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'trailer': '\n= %(trailer)s\n',
        'header': '\n= %(header)s\n',
        'render': '\n= %(code)s\n',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'pug',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'javascript',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/pug?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/pug?inj=*&tpl=%s'
    plugin = Pug


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (2, 2, '- var %s = true', { 'prefix' : 'a\n', 'suffix' : '//' }),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),

        (1, 0, 'a(href=\'%s\')', { 'prefix' : '1\')', 'suffix' : '//' }),
        (1, 0, 'a(href="%s")', { 'prefix' : '1")', 'suffix' : '//' }),
        (0, 0, '#container.%s', {  }),
        (2, 1, '#{%s}', { 'prefix' : '1}', 'suffix' : '//' }),

        (2, 2, '- var %s = true', { 'prefix' : 'a\n', 'suffix' : '//' }),
        (2, 1, '- var a = %s', { 'prefix': '1\n', 'suffix' : '//' }),

    ]

    def test_reflection_quotes(self):

        obj, data = self._get_detection_obj_data(self.url % '')

        if obj.get('execute'):
            result = obj.execute("""echo 1"2"'3'\\"\\'""")
            self.assertEqual(result, """123&quot;'""")

        if not self.url_blind:
            return

        obj, data = self._get_detection_obj_data(self.url_blind % '')    
        if obj.get('execute_blind'):
            self.assertTrue(obj.execute_blind("""echo 1"2"'3'\\"\\'"""))