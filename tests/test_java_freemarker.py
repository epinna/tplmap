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
        'trailer_tag': '${%(trailer)s?c}',
        'header_tag': '${%(header)s?c}',
        'render_tag': '${%(payload)s}',
        'write': True,
        'read': True
    }

    url = 'http://127.0.0.1:15003/freemarker?inj=*&tpl=%s'

    plugin = Freemarker
    
    reflection_tests = [
        (1, 1, '%s', {}),
        (1, 1, 'AAA%sAAA', {}),
        (1, 1, '${ %s }', { 'prefix': '1}', 'suffix': '' }),
        (1, 1, '<#assign s = %s>', { 'prefix': '1>', 'suffix': '' }),
        (1, 1, '<#-- %s -->', { 'prefix': '-->', 'suffix': '<#--' }),
        (1, 1, '<#if 1 == %s></#if>', { 'prefix': '1>', 'suffix' : ''}),
        (1, 2, '<#if %s == 1></#if>', { 'prefix': 'true>', 'suffix' : ''}),
        (1, 3, '<#list [%s] as a></#list>', { 'prefix' : '1] as a></#list><#list [1] as a>', 'suffix' : ''}),
        (1, 5, '<#list %s as a></#list>', { 'prefix' : '[1] as a></#list><#list [1] as a>', 'suffix' : ''})

    ]
    
    def test_download(self):
        pass
        
    def test_upload(self):
        pass