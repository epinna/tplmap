import unittest
import requests
import os
import sys
import random

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from plugins.engines.nunjucks import Nunjucks
from basetest import BaseTest


class NunjucksTests(unittest.TestCase, BaseTest):

    expected_data = {
        'language': 'javascript',
        'engine': 'nunjucks',
        'evaluate' : 'javascript' ,
        'execute' : True,
        'read' : True,
        'write' : True,
        'prefix' : '',
        'suffix': '',
        'trailer': '{{%(trailer)s}}',
        'header': '{{%(header)s}}',
        'render': '{{%(code)s}}',
        'bind_shell' : True,
        'reverse_shell': True
    }

    expected_data_blind = {
        'language': 'javascript',
        'engine': 'nunjucks',
        'evaluate_blind' : 'javascript',
        'blind': True,
        'execute_blind' : True,
        'write': True,
        'prefix' : '',
        'suffix' : '',
        'bind_shell' : True,
        'reverse_shell': True
    }

    url = 'http://127.0.0.1:15004/nunjucks?inj=*&tpl=%s'
    url_blind = 'http://127.0.0.1:15004/blind/nunjucks?inj=*&tpl=%s'
    plugin = Nunjucks


    blind_tests = [
        (0, 0, 'AAA%sAAA', {}),
        (5, 1, "{% for item in %s %}{% endfor %}", {'prefix': '1 %}{% endfor %}{% for a in [1] %}', 'suffix' : ''}),
        (1, 3, "{% if 1 in [%s] %}{% endif %}", {'prefix': '1} %}', 'suffix' : ''}),
    ]

    reflection_tests = [
        (0, 0, '%s', {}),
        (0, 0, 'AAA%sAAA', {}),
        (1, 0, "{{ %s }}", { 'prefix': '1}}', 'suffix' : '{{1' }),
        (0, 0, "{% block title %}%s{% endblock %}", {}),
        (1, 0, "{% set foo = '%s' %}", {  'prefix': "1' %}", 'suffix' : '' }),
        (5, 2, "{% set %s = 1 %}", {  'prefix': 'a = 1 %}', 'suffix' : '' }),
        (5, 1, "{% for item in %s %}{% endfor %}", {'prefix': '1 %}{% endfor %}{% for a in [1] %}', 'suffix' : ''}),
        (1, 0, "{% if %s == 1 %}{% endif %}", {'prefix': '1 %}', 'suffix' : ''}),
        (1, 2, "{% if 1 in %s %}{% endif %}", {'prefix': '"1" %}', 'suffix' : ''}),
        (1, 3, "{% if 1 in [%s] %}{% endif %}", {'prefix': '1} %}', 'suffix' : ''}),
        
        # Comment blocks
        (5, 1, '{# %s #}', { 'prefix' : '#}', 'suffix' : '{#' }),
    ]