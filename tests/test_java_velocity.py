import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.velocity import Velocity
from basetest import BaseTest

class VelocityTest(unittest.TestCase, BaseTest):
    
    expected_data = {
        'language': 'java',
        'engine': 'velocity',
        'trailer_tag': '\n#set($t=%(trailer)s)\n$t',
        'header_tag': '#set($h=%(header)s)\n$h\n',
        'render_tag': '#set($p=%(payload)s)\n$p\n',
    }
    
    url = 'http://127.0.0.1:15003/velocity?inj=*&tpl=%s'

    plugin = Velocity
    
    reflection_tests = [
        (1, '%s', {}),
        (1, 'AAA%sAAA', {})
    ]

    def test_download(self):
        pass
        
    def test_upload(self):
        pass