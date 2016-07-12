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
from basetest import BaseTest

class Jinja2Test(unittest.TestCase, BaseTest):

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

    url = 'http://127.0.0.1:15001/reflect/jinja2?tpl=%s&inj=*'
    plugin = Jinja2

    reflection_tests = [
        (1, '%s', {}),
        (1, 'AAA%sAAA', {}),

        # Reflecting tag ${} context
        (1, '{{%s}}', { 'prefix': '1}}', 'suffix' : '' }),
        (2, '{{ \'%s\' }}', { 'prefix': '1\'}}', 'suffix' : '' }),
        (2, '{{ "%s" }}', { 'prefix': '1"}}', 'suffix' : '' }),
        (2, '{{ """%s""" }}', { 'prefix': '1"}}', 'suffix' : '' }), # {{"""%s"""}} -> {{"""1"}}
        (3, '{{ \'a\'|join(%s) }}', { 'prefix': '1)}}', 'suffix' : '' }),
        (3, '{{ \'a\'|join(\'%s\') }}', { 'prefix': '1\')}}', 'suffix' : '' }),
        (3, '{{ \'a\'|join("%s") }}', { 'prefix': '1")}}', 'suffix' : '' }),
        (3, '{{ \'a\'|join("""%s""") }}', { 'prefix': '1")}}', 'suffix' : '' }), # {{("""%s""")}} -> {{("""1")]}}

        (4, '{{[%s]}}', { 'prefix': '1]}}', 'suffix' : '' }),
        (4, '{{ [\'%s\'] }}', { 'prefix': '1\']}}', 'suffix' : '' }),
        (4, '{{ ["%s"] }}', { 'prefix': '1"]}}', 'suffix' : '' }),
        (4, '{{ ["""%s"""] }}', { 'prefix': '1"]}}', 'suffix' : '' }), # {{["""%s"""]}} -> {{["""1"]}}
        (4, '{{ \'a\'|join([%s]) }}', { 'prefix': '1])}}', 'suffix' : '' }),
        (4, '{{ \'a\'|join([\'%s\'])) }}', { 'prefix': '1\'])}}', 'suffix' : '' }),
        (4, '{{ \'a\'|join(["%s"]) }}', { 'prefix': '1"])}}', 'suffix' : '' }), # {{["""%s"""]}} -> {{["""1"]}}

        (5, '{{{%s}}}', { 'prefix': '1:1}}}', 'suffix' : '' }),
        (5, '{{{1:%s}}}', { 'prefix': '1}}}', 'suffix' : '' }),
        (5, '{{ {1:\'%s\'} }}', { 'prefix': '1\'}}}', 'suffix' : '' }),
        (5, '{{ {1:"%s"} }}', { 'prefix': '1"}}}', 'suffix' : '' }),
        (5, '{{ {1:"""%s"""} }}', { 'prefix': '1"}}}', 'suffix' : '' }),
        (5, '{{{%s:1}}}', { 'prefix': '1:1}}}', 'suffix' : '' }),
        (5, '{{ {\'%s\':1} }}', { 'prefix': '1\':1}}}', 'suffix' : '' }),
        (5, '{{ {"%s":1} }}', { 'prefix': '1":1}}}', 'suffix' : '' }),
        (5, '{{ {"""%s""":1}} }', { 'prefix': '1":1}}}', 'suffix' : '' }),


        # if and for blocks context
        (2, '{%% if %s: %%}\n{%% endif %%}', { 'prefix' : '\'a\': %}\n', 'suffix' : '\n' }),
        (2, '{%% for a in %s: %%}\n{%% endfor %%}', { 'prefix' : '\'a\': %}\n', 'suffix' : '\n' }),
        (2, '{%% if %s==1: %%}\n{%% endif %%}', { 'prefix' : '\'a\': %}\n', 'suffix' : '\n' }),
        (2, '{%% if \'%s\'==1: %%}\n{%% endif %%}', { 'prefix' : 'a\': %}\n', 'suffix' : '\n' }),
        (2, '{%% if "%s"==1: %%}\n{%% endif %%}', { 'prefix' : 'a": %}\n', 'suffix' : '\n' }),
        (2, '{%% if """%s"""==1: %%}\n{%% endif %%}', { 'prefix' : 'a": %}\n', 'suffix' : '\n' }), # if """%s""": -> if """1":
        (3, '{%% if (%s)==1: %%}\n{%% endif %%}', { 'prefix' : '\'a\'): %}\n', 'suffix' : '\n' }),
        (3, '{%% if (\'%s\')==1: %%}\n{%% endif %%}', { 'prefix' : 'a\'): %}\n', 'suffix' : '\n' }),
        (3, '{%% if ("%s")==1: %%}\n{%% endif %%}', { 'prefix' : 'a"): %}\n', 'suffix' : '\n' }),
        (3, '{%% if ("""%s""")==1: %%}\n{%% endif %%}', { 'prefix' : 'a"): %}\n', 'suffix' : '\n' }), # if ("""%s"""): -> if ("""1"):

        (4, '{%% for a in {%s}: %%}\n{%% endfor %%}', { 'prefix' : '1:1}: %}\n', 'suffix' : '\n' }),
        (4, '{%% if [%s]==1: %%}\n{%% endif %%}', { 'prefix' : '\'a\']: %}\n', 'suffix' : '\n' }),
        (4, '{%% if [\'%s\']==1: %%}\n{%% endif %%}', { 'prefix' : 'a\']: %}\n', 'suffix' : '\n' }),
        (4, '{%% if ["%s"]==1: %%}\n{%% endif %%}', { 'prefix' : 'a"]: %}\n', 'suffix' : '\n' }),
        (4, '{%% if ["""%s"""]==1: %%}\n{%% endif %%}', { 'prefix' : 'a"]: %}\n', 'suffix' : '\n' }), # if ["""%s"""]: -> if ["""1"]:
        (4, '{%% if ([%s])==1: %%}\n{%% endif %%}', { 'prefix' : '\'a\']): %}\n', 'suffix' : '\n' }),
        (4, '{%% if ([\'%s\'])==1: %%}\n{%% endif %%}', { 'prefix' : 'a\']): %}\n', 'suffix' : '\n' }),
        (4, '{%% if (["%s"])==1: %%}\n{%% endif %%}', { 'prefix' : 'a"]): %}\n', 'suffix' : '\n' }),
        (4, '{%% if (["""%s"""])==1: %%}\n{%% endif %%}', { 'prefix' : 'a"]): %}\n', 'suffix' : '\n' }), # if (["""%s"""]): -> if (["""1"]):

        (5, '{%% for a in {%s}: %%}\n{%% endfor %%}', { 'prefix' : '1:1}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {%s:1}==1: %%}\n{%% endif %%}', { 'prefix' : '1:1}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {\'%s\':1}==1: %%}\n{%% endif %%}', { 'prefix' : 'a\':1}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {"%s":1}==1: %%}\n{%% endif %%}', { 'prefix' : 'a":1}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {"""%s""":1}==1: %%}\n{%% endif %%}', { 'prefix' : 'a":1}: %}\n', 'suffix' : '\n' }), # if {"""%s""":1}: -> if {"""1":1}:
        (5, '{%% if {1:%s}==1: %%}\n{%% endif %%}', { 'prefix' : '1}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {1:\'%s\'}==1: %%}\n{%% endif %%}', { 'prefix' : 'a\'}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {1:"%s"}==1: %%}\n{%% endif %%}', { 'prefix' : 'a"}: %}\n', 'suffix' : '\n' }),
        (5, '{%% if {1:"""%s"""}==1: %%}\n{%% endif %%}', { 'prefix' : 'a"}: %}\n', 'suffix' : '\n' }), # if {1:"""%s""":1}: -> if {1:"""1"}:

    ]

    def test_reflection_limit(self):

        obj, data = self._get_detection_obj_data('http://127.0.0.1:15001/limit/jinja2?tpl=%s&inj=*&limit=8' % '')

        expected_data = { 'render_tag' : self.expected_data['render_tag'] }

        self.assertEqual(data, expected_data)

    def test_reflection_quotes(self):

        obj, data = self._get_detection_obj_data(self.url % '')

        result = obj.execute('echo 1"2"')
        self.assertEqual(result, '12')

        result = obj.execute('echo 1\\"2')
        self.assertEqual(result, '1"2')
