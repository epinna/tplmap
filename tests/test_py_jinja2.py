import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.jinja2 import Jinja2
from core.channel import Channel

class Jinja2Test(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'jinja2',
        'eval' : 'python' ,
        'exec' : True,
        'os' : 'posix-darwin',
        'trailer_tag': '{{%(trailer)s}}',
        'header_tag': '{{%(header)s}}',
        'render_tag': '{{%(payload)s}}',
    }

    def test_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel).detect()
        self.assertEqual(channel.data, self.expected_data)


    def test_reflection_context_text(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel).detect()
        self.assertEqual(channel.data, self.expected_data)

    def test_reflection_context_code(self):
        template = '{{%s}}'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel).detect()

        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix' : '""}}', 'suffix' : '{{""' })

        self.assertEqual(channel.data, expected_data)

    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/jinja2?tpl=%s&inj=*&limit=8' % template
        })

        Jinja2(channel).detect()

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }

        self.assertEqual(channel.data, expected_data)
