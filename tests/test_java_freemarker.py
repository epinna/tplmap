import unittest
import requests
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.freemarker import Freemarker
from core.channel import Channel
from utils import rand
from utils import strings

class FreemarkerTest(unittest.TestCase):


    expected_data = {
        'language': 'java',
        'engine': 'freemarker',
        'exec' : True,
        'trailer_tag': '${%(trailer)s}',
        'header_tag': '${%(header)s}',
        'render_tag': '${%(payload)s}',
        'write': True
    }

    def test_reflection(self):

        template = '%s'

        channel = Channel({
            'url' : 'http://127.0.0.1:15003/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)


    def test_reflection_within_text(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15003/freemarker?inj=*'
        })
        Freemarker(channel).detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)

    def test_file_write(self):
        template = 'AAAA%sAAAA'

        channel = Channel({
            'url' : 'http://127.0.0.1:15003/freemarker?inj=*'
        })
        freemarkerobj = Freemarker(channel)
        freemarkerobj.detect()
        del channel.data['os']
        self.assertEqual(channel.data, self.expected_data)
        
        remote_temp_path = '/tmp/tplmap_%s.tmp' % rand.randstr_n(10)
        
        # Send long binary
        data = open('/bin/ls', 'rb').read()
        freemarkerobj.write(data, remote_temp_path)
        self.assertEqual(freemarkerobj._md5(remote_temp_path), strings.md5(data))
        freemarkerobj.execute('rm %s' % (remote_temp_path))
        
        # Send short ASCII data, without removing it
        data = 'SHORT ASCII DATA'
        freemarkerobj.write(data, remote_temp_path)
        self.assertEqual(freemarkerobj._md5(remote_temp_path), strings.md5(data))

        # Try to append data without --force-overwrite and re-check the previous md5
        freemarkerobj.write('APPENDED DATA', remote_temp_path)
        self.assertEqual(freemarkerobj._md5(remote_temp_path), strings.md5(data))
        
        # Now set --force-overwrite and rewrite new data on the same file
        freemarkerobj.channel.args['force_overwrite'] = True
        data = 'NEW DATA'
        freemarkerobj.write(data, remote_temp_path)
        self.assertEqual(freemarkerobj._md5(remote_temp_path), strings.md5(data))
        freemarkerobj.execute('rm %s' % (remote_temp_path))



