import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.twig import Twig
from core.channel import Channel
from basetest import BaseTest

class TwigTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'php',
        'engine': 'twig',
        'trailer_tag': '{{%(trailer)s}}',
        'header_tag': '{{%(header)s}}',
        'render_tag': '{{%(payload)s}}',
    }
    
    url = 'http://127.0.0.1:15002/twig-1.24.1-secured.php?tpl=%s&inj=*'
    
    plugin = Twig
    
    reflection_tests = [
        (1, 1, "%s", {}),
        (1, 1, "AAA%sAAA", {})
    ]
    
    # Defuse download tests, capabilities not present
    def test_download(self):
        pass
        
    # Defuse upload tests, capabilities not present
    def test_upload(self):
        pass    