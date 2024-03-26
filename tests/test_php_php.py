import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.languages.php import Php
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest, EXTRA_DOWNLOAD


class PhpTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'php',
        'evaluate' : 'php' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': """%(code)s""",
        'header': """print_r('%(header)s');""",
        'trailer': """print_r('%(trailer)s');""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'php',
        'engine': 'php',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'php',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://localhost:15002/eval.php?inj=*&tpl=%s'
    url_blind = 'http://localhost:15002/eval.php?inj=*&tpl=%s&blind=1'
    plugin = Php


    blind_tests = [
        (0, 0, '%s', {}),
        (1, 3, '["%s"]', { 'prefix': '1"];', 'suffix' : '//' }),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (2, 0, 'if("%s"=="2"){}', { 'prefix' : '1")', 'suffix' : '//'}),
        (1, 3, '["%s"]', { 'prefix': '1"];', 'suffix' : '//' }),
    ]
    
    def test_download(self):

        # This is overriden due to the slight
        # difference from the base test_download()
        # obj.read('/dev/null') -> None

        obj, data = self._get_detection_obj_data(self.url % '')
        self.assertEqual(data, self.expected_data)

        if not EXTRA_DOWNLOAD:
            return

        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, obj.read(readable_file))

        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, obj.read(readable_file))

        # Non existant file
        self.assertEqual(None, obj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, obj.read('/etc/shadow'))
        # Empty file
        self.assertEqual(None, obj.read('/dev/null'))
