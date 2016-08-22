import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.dust import Dust
from basetest import BaseTest


class DustTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'dust',
        'write' : True,
        'execute_blind' : True,
        'prefix' : '',
        'suffix': '',
        'header': '%s',
        'trailer': '%s',
        'bind_shell' : True,
        'reverse_shell': True,
        'blind': True,
        'evaluate_blind': 'javascript'
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'dust',
        'blind': True,
        'execute_blind' : True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True,
        'evaluate_blind': 'javascript'
    }

    url = 'http://127.0.0.1:15004/dust?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/dust?inj=*&tpl=%s'
    plugin = Dust


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (0, 0, '{%s|s}', { }),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (0, 0, '{%s}', { }),
        (0, 0, '{%s|s}', { }),
        (1, 0, '{!%s!}', { 'prefix' : '!}', 'suffix' : '{!' })
    ]
    
    def test_upload(self):
        pass
        
    def test_download(self):
        pass