from utils.loggers import log
from core.plugin import Plugin
from utils import rand
from core import languages
import string

class Twig(Plugin):

    actions = {
        'render' : {
            'render': '{{%(code)s}}',
            'header': '{{%(header)s}}',
            'trailer': '{{%(trailer)s}}',
            # {{7*'7'}} and a{#b#}c work in freemarker as well
            # {%% set a=%i*%i %%}{{a}} works in Nunjucks as well
            'render_test': '"%(s1)s\n"|nl2br' % { 
                's1' : rand.randstrings[0]
            },
            'render_expected': '%(res)s<br />' % { 
                'res' : rand.randstrings[0]
            }
        }
    }
    contexts = [

        # Text context, no closures
        { 'level': 0 },

        { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '{{1', 'closures' : languages.php_ctx_closures },
        { 'level': 1, 'prefix': '%(closure)s %%}', 'suffix' : '', 'closures' : languages.php_ctx_closures },
        { 'level': 5, 'prefix': '%(closure)s %%}{%% endfor %%}{%% for a in [1] %%}', 'suffix' : '', 'closures' : languages.php_ctx_closures },

        # This escapes string "inter#{"asd"}polation"
        #{ 'level': 5, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : languages.php_ctx_closures },

        # This escapes string {% set %s = 1 %}
        { 'level': 5, 'prefix': '%(closure)s = 1 %%}', 'suffix' : '', 'closures' : languages.php_ctx_closures },

    ]

    language = 'php'
