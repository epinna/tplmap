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
        'trailer_tag': '{%(trailer)s}',
        'header_tag': '{%(header)s}',
        'render_tag': '{%(payload)s}',
    }
    
    url = 'http://127.0.0.1:15002/smarty-3.1.29-secured.php?inj=*&tpl=%s'
    plugin = Smarty
    
    reflection_tests = [
        (1, 1, '%s', {}),
        (1, 1, 'AAA%sAAA', {})
    ]

    def test_download(self):
        pass
        
    def test_upload(self):
        pass