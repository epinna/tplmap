from utils.loggers import log
from plugins.languages import php
from utils import rand
import string

class Twig(php.Php):
    
    def init(self):

        self.set_actions({
            'render' : {
                'render': '{{%(code)s}}',
                'header': '{{%(header)s}}',
                'trailer': '{{%(trailer)s}}',
                # {{7*'7'}} and a{#b#}c work in freemarker as well
                # {%% set a=%i*%i %%}{{a}} works in Nunjucks as well
                'test_render': '"%(s1)s\n"|nl2br' % { 
                    's1' : rand.randstrings[0]
                },
                'test_render_expected': '%(res)s<br />' % { 
                    'res' : rand.randstrings[0]
                }
            }
        })
        
        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '{{1', 'closures' : php.ctx_closures },
            { 'level': 1, 'prefix': '%(closure)s %%}', 'suffix' : '', 'closures' : php.ctx_closures },
            { 'level': 5, 'prefix': '%(closure)s %%}{%% endfor %%}{%% for a in [1] %%}', 'suffix' : '', 'closures' : php.ctx_closures },

            # This escapes string "inter#{"asd"}polation"
            #{ 'level': 5, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : php.ctx_closures },

            # This escapes string {% set %s = 1 %}
            { 'level': 5, 'prefix': '%(closure)s = 1 %%}', 'suffix' : '', 'closures' : php.ctx_closures },

        ])
