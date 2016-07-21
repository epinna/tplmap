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
        'trailer': '{{%(trailer)s}}',
        'header': '{{%(header)s}}',
        'render': '{{%(payload)s}}',
    }
    
    url = 'http://127.0.0.1:15002/twig-1.24.1-secured.php?tpl=%s&inj=*'
    
    plugin = Twig
    
    reflection_tests = [
        (1, 1, "%s", {}),
        (1, 1, "AAA%sAAA", {}),
        (1, 1, "{{ %s }}", { 'prefix': '1}}', 'suffix' : '{{1' }),
        (1, 1, "{% block title %}%s{% endblock %}", {}),
        (1, 1, "{% set foo = '%s' %}", {  'prefix': "1' %}", 'suffix' : '' }),
        (5, 2, "{% set %s = 1 %}", {  'prefix': 'a = 1 %}', 'suffix' : '' }),
        (5, 1, "{% for item in %s %}{% endfor %}", {'prefix': '1 %}{% endfor %}{% for a in [1] %}', 'suffix' : ''}),
        (1, 1, "{% if %s == 1 %}{% endif %}", {'prefix': '1 %}', 'suffix' : ''}),
        (1, 2, "{% if 1 in %s %}{% endif %}", {'prefix': '"1" %}', 'suffix' : ''}),
        (1, 3, "{% if 1 in [%s] %}{% endif %}", {'prefix': '1] %}', 'suffix' : ''}),
        #(1, 4, "{{ \"iterpo#{%s}lation\" }}", { 'prefix': '1}}}', 'suffix' : '' }),
    ]
    
    # Defuse download tests, capabilities not available
    def test_download(self):
        pass
        
    # Defuse upload tests, capabilities not available
    def test_upload(self):
        pass    