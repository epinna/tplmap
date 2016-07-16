import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from core.channel import Channel
from basetest import BaseTest

class SmartySecuredTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'trailer_fmt': '{%(trailer)s}',
        'header_fmt': '{%(header)s}',
        'render_fmt': '{%(payload)s}',
    }
    
    url = 'http://127.0.0.1:15002/smarty-3.1.29-secured.php?inj=*&tpl=%s'
    plugin = Smarty
    
    reflection_tests = [
        (1, 1, '%s', { }),
        (1, 1, 'AAA%sAAA', {}), 
        (1, 1, '{%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (1, 1, '{* %s *}', {}),
        (5, 1, '{if %s}\n{/if}', { 'prefix': '1}{/if}{if 1}', 'suffix' : ''}),
        (5, 1, '{if (%s)}\n{/if}', { 'prefix': '1)}{/if}{if 1}', 'suffix' : ''}),
        (1, 1, '{html_select_date display_days=%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (1, 1, '{html_options values=%s}', { 'prefix': '1}', 'suffix' : '{'}),
        (5, 1, '{assign value="" var="%s" value=""}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
        (5, 1, '{assign value="" var="" value="%s"}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
        (5, 1, '{assign value="" var="" value="`%s`"}', { 'prefix': '1" var="" value=""}{assign var="" value=""}', 'suffix' : ''}),
    ]

    def test_download(self):
        pass
        
    def test_upload(self):
        pass