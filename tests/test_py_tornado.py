import unittest
import requests
import os
import sys
import random

sys.path.insert(10, os.path.join(sys.path[0], '..'))
from plugins.engines.tornado import Tornado
from core.channel import Channel
from utils import rand
from utils import strings
from basetest import BaseTest

class TornadoTest(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'python',
        'engine': 'tornado',
        'evaluate' : 'python' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix': '',
        'suffix': '',
        'trailer': '{{%(trailer)s}}',
        'header': '{{%(header)s}}',
        'render': '{{%(code)s}}',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'python',
        'engine': 'tornado',
        'evaluate_blind': 'python',
        'execute_blind': True,
        'write': True,
        'blind': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15001/reflect/tornado?tpl=%s&inj=*'
    url_blind = 'http://127.0.0.1:15001/blind/tornado?tpl=%s&inj=*'

    plugin = Tornado

    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (1, 2, '{%% for a in %s %%}\n{%% end %%}', { 'prefix' : '"1"%}', 'suffix' : '' }),
    ]
    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),

        # Reflecting tag ${} context
        (1, 1, '{{%s}}', { 'prefix': '1}}', 'suffix' : '' }),
        (1, 1, '{{ \'%s\' }}', { 'prefix': '1\'}}', 'suffix' : '' }),
        (1, 1, '{{ "%s" }}', { 'prefix': '1"}}', 'suffix' : '' }),
        (1, 3, '{{ """%s""" }}', { 'prefix': '1"""}}', 'suffix' : '' }), # {{"""%s"""}} -> {{"""1"}}
        
        (1, 4, '{{[%s]}}', { 'prefix': '1]}}', 'suffix' : '' }),
        (1, 3, '{{ [\'%s\'] }}', { 'prefix': '1\']}}', 'suffix' : '' }),
        (1, 3, '{{ ["%s"] }}', { 'prefix': '1"]}}', 'suffix' : '' }),
        (1, 3, '{{ ["""%s"""] }}', { 'prefix': '1"""]}}', 'suffix' : '' }), # {{["""%s"""]}} -> {{["""1"]}}
        
        # # if and for blocks context with {% %}
        (1, 1, '{%% if %s: %%}\n{%% end %%}', { 'prefix' : '1%}', 'suffix' : '' }),
        (1, 2, '{%% for a in %s: %%}\n{%% end %%}', { 'prefix' : '"1"%}', 'suffix' : '' }),
        (1, 1, '{%% if %s==1 %%}\n{%% end %%}', { 'prefix' : '1%}', 'suffix' : '' }),
        (1, 1, '{%% if \'%s\'==1 %%}\n{%% end %%}', { 'prefix' : '1\'%}', 'suffix' : '' }),
        (1, 1, '{%% if "%s"==1 %%}\n{%% end %%}', { 'prefix' : '1"%}', 'suffix' : '' }),
        (1, 3, '{%% if """%s"""==1 %%}\n{%% end %%}', { 'prefix' : '1"""%}', 'suffix' : '' }), # if """%s""": -> if """1":
        (1, 2, '{%% if (1, %s)==1 %%}\n{%% end %%}', { 'prefix' : '1)%}', 'suffix' : '' }),
        (1, 2, '{%% if (1, \'%s\')==1 %%}\n{%% end %%}', { 'prefix' : '1\')%}', 'suffix' : '' }),
        (1, 2, '{%% if (1, "%s")==1 %%}\n{%% end %%}', { 'prefix' : '1")%}', 'suffix' : '' }),
        (1, 3, '{%% if (1, """%s""")==1 %%}\n{%% end %%}', { 'prefix' : '1""")%}', 'suffix' : '' }), # if (1, """%s"""): -> if (1, """1"):
        
        (1, 3, '{%% if [%s]==1 %%}\n{%% end %%}', { 'prefix' : '1]%}', 'suffix' : '' }),
        (1, 3, '{%% if [\'%s\']==1 %%}\n{%% end %%}', { 'prefix' : '1\']%}', 'suffix' : '' }),
        (1, 3, '{%% if ["%s"]==1 %%}\n{%% end %%}', { 'prefix' : '1"]%}', 'suffix' : '' }),
        (1, 3, '{%% if ["""%s"""]==1 %%}\n{%% end %%}', { 'prefix' : '1"""]%}', 'suffix' : '' }), # if ["""%s"""]: -> if ["""1"]:
        (1, 5, '{%% if (1, [%s])==1 %%}\n{%% end %%}', { 'prefix' : '1])%}', 'suffix' : '' }),
        (1, 5, '{%% if (1, [\'%s\'])==1 %%}\n{%% end %%}', { 'prefix' : '1\'])%}', 'suffix' : '' }),
        (1, 5, '{%% if (1, ["%s"])==1 %%}\n{%% end %%}', { 'prefix' : '1"])%}', 'suffix' : '' }),
        (1, 5, '{%% if (1, ["""%s"""])==1 %%}\n{%% end %%}', { 'prefix' : '1"""])%}', 'suffix' : '' }), # if (1, ["""%s"""]): -> if (1, ["""1"]):
        
        (1, 3, '{%% for a in {%s} %%}\n{%% end %%}', { 'prefix' : '1}%}', 'suffix' : '' }),
        (1, 3, '{%% if {%s:1}==1 %%}\n{%% end %%}', { 'prefix' : '1}%}', 'suffix' : '' }),
        (1, 3, '{%% if {\'%s\':1}==1 %%}\n{%% end %%}', { 'prefix' : '1\'}%}', 'suffix' : '' }),
        (1, 3, '{%% if {"%s":1}==1 %%}\n{%% end %%}', { 'prefix' : '1"}%}', 'suffix' : '' }),
        (1, 3, '{%% if {"""%s""":1}==1 %%}\n{%% end %%}', { 'prefix' : '1"""}%}', 'suffix' : '' }), # if {"""%s""":1}: -> if {"""1":1}:
        (1, 3, '{%% if {1:%s}==1 %%}\n{%% end %%}', { 'prefix' : '1}%}', 'suffix' : '' }),
        (1, 3, '{%% if {1:\'%s\'}==1 %%}\n{%% end %%}', { 'prefix' : '1\'}%}', 'suffix' : '' }),
        (1, 3, '{%% if {1:"%s"}==1 %%}\n{%% end %%}', { 'prefix' : '1"}%}', 'suffix' : '' }),
        (1, 3, '{%% if {1:"""%s"""}==1 %%}\n{%% end %%}', { 'prefix' : '1"""}%}', 'suffix' : '' }), # if {1:"""%s""":1}: -> if {1:"""1"}:
        
        
        # # Comment blocks
        (5, 1, '{# %s #}', { 'prefix' : '#}', 'suffix' : '{#' }),

    ]
