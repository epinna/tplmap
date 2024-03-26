import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.dot import Dot
from basetest import BaseTest


class DotTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'dot',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': '{{=%(code)s}}',
        'header': '{{=%(header)s}}',
        'trailer': '{{=%(trailer)s}}',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'dot',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'javascript',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/dot?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/dot?inj=*&tpl=%s'
    plugin = Dot


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 1, "{{ %s }}", { 'prefix': '1;}}', 'suffix' : '{{1;' }),
    ]