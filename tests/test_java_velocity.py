import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.velocity import Velocity
from core.channel import Channel
from core.checks import detect_template_injection
from basetest import BaseTest

class VelocityTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'java',
        'engine': 'velocity',
        'execute' : True,
        'trailer': '\n#set($t=%(trailer)s)\n${t}\n',
        'header': '\n#set($h=%(header)s)\n${h}\n',
        'render': '%(code)s',
        'write': True,
        'read': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'java',
        'engine': 'velocity',
        'blind': True,
        'execute_blind' : True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }
    
    url = 'http://127.0.0.1:15003/velocity?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15003/velocity?inj=*&tpl=%s&blind=1'

    plugin = Velocity

    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (3, 1, '#macro(d)%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, '#set( $a = "%s" )', { 'prefix' : '1")', 'suffix': ''}),
        (1, 0, '#if(1 == %s)\n#end', { 'prefix' : '1)', 'suffix': ''}),
        (3, 1, '#if(%s == 1)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (3, 1, '#foreach($item in %s)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (0, 0, '## comment %s', { }),
        # TODO: fix those, they used to work
        #(5, 0, '#[[%s]]# ', { }),        
        (0, 0, '${%s}', {}),
        (0, 0, '${(%s)}', {}),
        (3, 1, '#define( %s )a#end', { 'prefix': '1)#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#define( $asd )%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#macro(d)%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
    ]


    def test_custom_injection_tag(self):

        template = '#* %s *#'

        channel = Channel({
            'url' : self.url.replace('*', '~') % template,
            'force_level': [ 5, 0 ],
            'injection_tag': '~',
            'technique': 'RT'
        })
        
        detect_template_injection(channel, [ self.plugin ])
        
        expected_data = self.expected_data.copy()
        expected_data.update({ 'prefix': '*#', 'suffix' : '#*'})
        
        del channel.data['os']
        
        self.assertEqual(channel.data, expected_data)