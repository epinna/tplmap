import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel

class MakoTest(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'eval' : 'python' ,
        'exec' : True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
    }

    def test_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*' % template
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)


    def test_reflection_context_text(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*' % template
        })
        Mako(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_reflection_context_code(self):
        template = '${%s}'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=*' % template
        })
        Mako(channel).detect()

        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix' : '}', 'suffix' : '${' })
        
        del channel.data['os']
        self.assertEqual(channel.data, expected_data)

    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/mako?tpl=%s&inj=*' % template
        })

        Mako(channel).detect()

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }
        
        self.assertEqual(channel.data, expected_data)
