import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.mako import Mako
from core.channel import Channel
from utils import rand
from utils import strings

class MakoTest(unittest.TestCase):

    expected_data = {
        'language': 'python',
        'engine': 'mako',
        'eval' : 'python' ,
        'exec' : True,
        'read': True,
        'write': True,
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
        
        
    def test_download(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?inj=*'
        })
        makoobj = Mako(channel)
        makoobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        # Normal ASCII file
        readable_file = '/etc/resolv.conf'
        content = open(readable_file, 'r').read()
        self.assertEqual(content, makoobj.read(readable_file))
        
        # Long binary file
        readable_file = '/bin/ls'
        content = open(readable_file, 'rb').read()
        self.assertEqual(content, makoobj.read(readable_file))    
        
        # Non existant file
        self.assertEqual(None, makoobj.read('/nonexistant'))
        # Unpermitted file
        self.assertEqual(None, makoobj.read('/etc/shadow'))
        # Empty file
        self.assertEqual('', makoobj.read('/dev/null'))

    def test_upload(self):

        channel = Channel({
            'url' : 'http://127.0.0.1:15001/reflect/mako?inj=*'
        })
        makoobj = Mako(channel)
        makoobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        makoobj.write(data, remote_temp_path)
        self.assertEqual(makoobj._md5(remote_temp_path), strings.md5(data))
        makoobj.execute('rm %s' % (remote_temp_path))
        
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        makoobj.write(data, remote_temp_path)
        self.assertEqual(makoobj._md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        makoobj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(makoobj._md5(remote_temp_path), strings.md5(data))
        
        # Now set --force-overwrite and rewrite new data on the same file
        makoobj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        makoobj.write(data, remote_temp_path)
        self.assertEqual(makoobj._md5(remote_temp_path), strings.md5(data))
        makoobj.execute('rm %s' % (remote_temp_path))
