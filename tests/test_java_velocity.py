import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.velocity import Velocity
from basetest import BaseTest

class VelocityTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'java',
        'engine': 'velocity',
        'trailer': '\n#set($t=%(trailer)s)\n${t}\n',
        'header': '\n#set($h=%(header)s)\n${h}\n',
        'render': '#set($c=%(code)s)\n${c}\n',
        'prefix': '',
        'suffix': '',
    }

    url = 'http://127.0.0.1:15003/velocity?inj=*&tpl=%s'
    url_blind = ''

    plugin = Velocity

    blind_tests = [
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (0, 0, '#set( $a = "%s" )', { 'prefix' : '1")', 'suffix': ''}),
        (0, 0, '#if(1 == %s)\n#end', { 'prefix' : '1)', 'suffix': ''}),
        (3, 1, '#if(%s == 1)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (3, 1, '#foreach($item in %s)\n#end', { 'prefix' : '1)#end#if(1==1)', 'suffix': ''}),
        (0, 0, '## comment %s', { }),
        # TODO: fix those, they used to work
        #(5, 0, '#* %s *#', { }),
        #(5, 0, '#[[%s]]# ', { }),        
        (0, 0, '${%s}', {}),
        (0, 0, '${(%s)}', {}),
        (3, 1, '#define( %s )a#end', { 'prefix': '1)#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#define( $asd )%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
        (3, 1, '#macro(d)%s#end', { 'prefix': '1#end#if(1==1)', 'suffix' : ''}),
    ]

    def test_download(self):
        pass

    def test_upload(self):
        pass
