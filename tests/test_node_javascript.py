import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.languages.javascript import Javascript
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest


class JavascriptTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'javascript',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'render': """%(code)s""",
        'header': """'%(header)s'+""",
        'trailer': """+'%(trailer)s'""",
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'javascript',
        'blind': True,
        'execute_blind' : True,
        'evaluate_blind' : 'javascript',
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/javascript?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/javascript?inj=*&tpl=%s'
    plugin = Javascript


    blind_tests = [
        (0, 0, '%s', {}),
        (2, 0, 'if("%s"=="2"){}', { 'prefix' : '1")', 'suffix' : '//'}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (2, 0, 'if("%s"=="2"){}', { 'prefix' : '1")', 'suffix' : '//'}),
        (1, 3, '["%s"]', { 'prefix': '1"];', 'suffix' : '//' }),
    ]
    
    def test_custom_injection_tag(self):

        template = '/* %s */'

        channel = Channel({
            'url' : self.url.replace('*', '~') % template,
            'force_level': [ 5, 0 ],
            'injection_tag': '~',
            'technique': 'RT'
        })
        
        detect_template_injection(channel, [ self.plugin ])
        
        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix': '*/', 'suffix' : '/*'})
        
        del channel.data['os']
        
        self.assertEqual(channel.data, expected_data)