import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.jinja2 import Jinja2
from core.channel import Channel
from utils import rand
from utils import strings

class Jinja2Test(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'jinja2',
        'eval' : 'python' ,
        'exec' : True,
        'read' : True,
        'write' : True,
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
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)


    def test_reflection_context_text(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_reflection_context_code(self):
        template = '{{%s}}'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*' % template
        })
        Jinja2(channel).detect()

        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix' : '""}}', 'suffix' : '{{""' })

        del channel.data['os']
        self.assertEqual(channel.data, expected_data)

    def test_reflection_limit(self):
        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/limit/jinja2?tpl=%s&inj=*&limit=8' % template
        })

        Jinja2(channel).detect()

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }
        
        self.assertEqual(channel.data, expected_data)

    def test_reflection_quotes(self):
        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?&inj=*',
        })

        jinja2 = Jinja2(channel)
        result = jinja2.execute('echo 1"2"')
        self.assertEqual(result, '12')
        
        result = jinja2.execute('echo 1\\"2')
        self.assertEqual(result, '1"2')
        
        
    def test_file_read(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?inj=*'
        })
        jinja2obj = Jinja2(channel)
        jinja2obj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, jinja2obj.read(readable_file))
        
        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, jinja2obj.read(readable_file))    
        
        # Non existant file
        self.assertEqual(None, jinja2obj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, jinja2obj.read('/etc/shadow'))
        # Empty file
        self.assertEqual('', jinja2obj.read('/dev/null'))

    def test_file_write(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/jinja2?inj=*'
        })
        jinja2obj = Jinja2(channel)
        jinja2obj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        jinja2obj.write(data, remote_temp_path)
        self.assertEqual(jinja2obj._md5(remote_temp_path), strings.md5(data))
        jinja2obj.execute('rm %s' % (remote_temp_path))
        
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        jinja2obj.write(data, remote_temp_path)
        self.assertEqual(jinja2obj._md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        jinja2obj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(jinja2obj._md5(remote_temp_path), strings.md5(data))
        
        # Now set --force-overwrite and rewrite new data on the same file
        jinja2obj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        jinja2obj.write(data, remote_temp_path)
        self.assertEqual(jinja2obj._md5(remote_temp_path), strings.md5(data))
        jinja2obj.execute('rm %s' % (remote_temp_path))
