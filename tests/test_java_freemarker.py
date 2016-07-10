import unittest
import requests
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.freemarker import Freemarker
from basetest import BaseTest

class FreemarkerTest(unittest.TestCase, BaseTest):


    expected_data = {
        'language': 'java',
        'engine': 'freemarker',
        'exec' : True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
        'write': True,
        'read': True
    }

    url = 'http://127.0.0.1:15003/freemarker?inj=*&tpl=%s'

    plugin = Freemarker
    
    reflection_tests = [
        (1, '%s', {}),
        (1, 'AAA%sAAA', {})
    ]