from utils.loggers import log
from core.plugin import Plugin
from utils import rand
from core import closures

class Twig(Plugin):

    actions = {
        'render' : {
            'render': '{{%(code)s}}',
            'header': '{{%(header)s}}',
            'trailer': '{{%(trailer)s}}'
        }
    }
    contexts = [
    
        # Text context, no closures
        { 'level': 0 },
    
        { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '{{1', 'closures' : closures.php_ctx_closures },
        { 'level': 1, 'prefix': '%(closure)s %%}', 'suffix' : '', 'closures' : closures.php_ctx_closures },
        { 'level': 5, 'prefix': '%(closure)s %%}{%% endfor %%}{%% for a in [1] %%}', 'suffix' : '', 'closures' : closures.php_ctx_closures },

        # This escapes string "inter#{"asd"}polation"
        #{ 'level': 5, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : closures.php_ctx_closures },

        # This escapes string {% set %s = 1 %}
        { 'level': 5, 'prefix': '%(closure)s = 1 %%}', 'suffix' : '', 'closures' : closures.php_ctx_closures },

    ]

    def detect_engine(self):

        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        # {{7*'7'}} and a{#b#}c work in freemarker as well
        payload = '{%% set a=%i*%i %%}{{a}}' % (randA, randB)
        expected = str(randA * randB)
        
        if expected == self.render(payload):
            self.set('language', 'php')
            self.set('engine', 'twig')
