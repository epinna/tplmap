from plugins.languages import python
from utils.loggers import log
from utils import rand
import re

class Mako(python.Python):
    
    def init(self):

        self.update_actions({
            'render' : {
                'render': '${%(code)s}',
                'header': '${%(header)s}',
                'trailer': '${%(trailer)s}'
            },
        })

        self.set_contexts([

            # Text context, no closures
            { 'level': 0 },

            # Normal reflecting tag ${}
            { 'level': 1, 'prefix': '%(closure)s}', 'suffix' : '', 'closures' : python.ctx_closures },

            # Code blocks
            # This covers <% %s %>, <%! %s %>, <% %s=1 %>
            { 'level': 1, 'prefix': '%(closure)s%%>', 'suffix' : '<%%#', 'closures' : python.ctx_closures },

            # If and for blocks
            # % if %s:\n% endif
            # % for a in %s:\n% endfor
            { 'level': 5, 'prefix': '%(closure)s#\n', 'suffix' : '\n', 'closures' : python.ctx_closures },

            # Mako blocks
            { 'level': 5, 'prefix' : '</%%doc>', 'suffix' : '<%%doc>' },
            { 'level': 5, 'prefix' : '</%%def>', 'suffix' : '<%%def name="t(x)">', 'closures' : python.ctx_closures },
            { 'level': 5, 'prefix' : '</%%block>', 'suffix' : '<%%block>', 'closures' : python.ctx_closures },
            { 'level': 5, 'prefix' : '</%%text>', 'suffix' : '<%%text>', 'closures' : python.ctx_closures},

        ])