import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
from core.checks import detect_template_injection
import utils.loggers
import logging

utils.loggers.stream_handler.setLevel(logging.FATAL)

class ChannelTest(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'evaluate' : 'python' ,
        'execute' : True,
        'write' : True,
        'read' : True,
        'trailer': '${%(trailer)s}',
        'header': '${%(header)s}',
        'render': '${%(code)s}',
        'prefix': '',
        'suffix': '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    def test_post_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/post/mako',
            'force_level': [ 0, 0 ],
            'data' : 'inj=*&othervar=1',
            'injection_tag': '*',
            'technique': 'R'

        })
        detect_template_injection(channel, [ Mako ])
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_url_reflection(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/url/mako/AA*AA',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'

        })

        detect_template_injection(channel, [ Mako ])
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_header_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/header/mako',
            'force_level': [ 0, 0 ],
            'headers' : [ 'User-Agent: *' ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_put_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/put/mako',
            'data' : 'inj=*&othervar=1',
            'request' : 'PUT',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_custom_injection_tag(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?tpl=%s&inj=~',
            'force_level': [ 0, 0 ],
            'injection_tag': '~',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        
    def test_reflection_multiple_point_tag(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?tpl=%s&asd=1&asd2=*&inj=*&inj2=*&inj3=*',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
    def test_reflection_multiple_point_no_tag(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?inj=asd&inj2=asd2',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
    def test_no_reflection(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?inj2=asd2',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'RT'
        })
        detect_template_injection(channel, [ Mako ])
        
        self.assertEqual(channel.data, {})

    def test_reflection_point_startswith(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/startswith/mako?inj=thismustexists*&startswith=thismustexists',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)    

    def test_reflection_point_dont_startswith(self):
        
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/startswith/mako?inj=*&startswith=thismustexists',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        self.assertEqual(channel.data, {})    
        

    def test_quotes(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?inj=asd',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'RT'
        })
        obj = detect_template_injection(channel, [ Mako ])

        result = obj.execute("""echo 1"2"'3'\\"\\'""")
        self.assertEqual(result, """123"'""")

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/blind/mako?inj=asd',
            'force_level': [ 0, 0 ],
            'injection_tag': '*',
            'technique': 'RT'
        })
        obj = detect_template_injection(channel, [ Mako ])
  
        self.assertTrue(obj.execute_blind("""echo 1"2"'3'\\"\\'"""))
                        
    def test_auth_reflection(self):

        channel = Channel({
            'url' : 'http://localhost:15001/reflect_cookieauth/mako?inj=asd*',
            'force_level': [ 0, 0 ],
            'headers' : [ 'Cookie: SID=SECRET' ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_wrong_auth_reflection(self):

        channel = Channel({
            'url' : 'http://localhost:15001/reflect_cookieauth/mako?inj=asd*',
            'force_level': [ 0, 0 ],
            'headers' : [ 'Cookie: SID=WRONGSECRET' ],
            'injection_tag': '*',
            'technique': 'R'
        })
        detect_template_injection(channel, [ Mako ])
        
        self.assertEqual(channel.data, {})