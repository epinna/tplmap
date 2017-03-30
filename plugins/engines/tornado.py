from plugins.languages import python
from utils.loggers import log
from utils import rand
import re

class Tornado(python.Python):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '{{%(code)s}}',
                'header': '{{%(header)s}}',
                'trailer': '{{%(trailer)s}}',
                'test_render': """'%(s1)s'}}{%% raw '%(s1)s'.join('%(s2)s') %%}{{'%(s2)s'""" % { 
                    's1' : rand.randstrings[0], 
                    's2' : rand.randstrings[1]
                },
                'test_render_expected': '%(res)s' % { 
                    'res' : rand.randstrings[0] + rand.randstrings[0].join(rand.randstrings[1]) + rand.randstrings[1]
                }
            }
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },
            
            # This covers {{%s}}
            { 'level': 1, 'prefix': '%(closure)s}}', 'suffix' : '', 'closures' : python.ctx_closures },

            # This covers {% %s %}
            { 'level': 1, 'prefix': '%(closure)s%%}', 'suffix' : '', 'closures' : python.ctx_closures },

            # Comment blocks
            { 'level': 5, 'prefix' : '#}', 'suffix' : '{#' },
    ])
