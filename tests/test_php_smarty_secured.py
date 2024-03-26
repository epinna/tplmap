import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest

class SmartySecuredTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'trailer': '{%(trailer)s}',
        'header': '{%(header)s}',
        'render': '%(code)s',
        'prefix' : '',
        'suffix' : '',
    }

    expected_data_blind = {
        'language': 'php',
        'engine': 'smarty',
        'evaluate_blind': 'php',
        'blind': True,
        'prefix' : '',
        'suffix' : '',
    }

    url = 'http://127.0.0.1:15002/smarty-3.1.32-secured.php?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15002/smarty-3.1.32-secured.php?inj=*&tpl=%s&blind=1'
    plugin = Smarty

    # The secured Smarty can't executes any PHP hence no sleep(1) hence no
    # blind tests for now
    blind_tests = [
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
        
        self.assertEqual(channel.data, expected_data)

    def test_download(self):
        pass

    def test_upload(self):
        pass
        
    def test_upload_blind(self):
        pass