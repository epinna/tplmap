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
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'trailer': '\n= %(trailer)s\n',
        'header': '\n= %(header)s\n',
        'render': '\n= %(code)s\n',
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'jade',
        'evaluate' : 'javascript',
        'blind': True,
        'blind_execute' : True,
        'execute': True,
        'prefix' : '',
        'suffix' : '',
    }

    url = 'http://127.0.0.1:15004/jade?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/jade?inj=*&tpl=%s'
    plugin = Jade


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (2, 2, '- var %s = true', { 'prefix' : 'a\n', 'suffix' : '//' }),
    ]
    
    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),

        (0, 0, 'a(href=\'%s\')', { 'prefix' : '1\')', 'suffix' : '//' }),
        (0, 0, 'a(href="%s")', { 'prefix' : '1")', 'suffix' : '//' }),
        (0, 0, '#container.%s', {  }),
        (2, 1, '#{%s}', { 'prefix' : '1}', 'suffix' : '//' }),

        (2, 2, '- var %s = true', { 'prefix' : 'a\n', 'suffix' : '//' }),
        (2, 1, '- var a = %s', { 'prefix': '1\n', 'suffix' : '//' }),

    ]
