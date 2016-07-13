from core.plugin import Plugin

class Python(Plugin):

    language_closures = {
        'close_single_double_quotes': [ '1\'', '1"' ],
        'str_int': [ '1', '"1"' ],
        'close_triple_quotes': [ '1"""' ],
        'close_dict': [ '}', ':1}' ],
        'close_funct_list': [ ')', ']' ],
        'close_if_loop': [ ':' ],
        'empty': [ '' ]
    }

    closure_levels = {
            1: [[ 'close_single_double_quotes', 'str_int' ]],
            2: [[ 'close_single_double_quotes', 'str_int' ], ['close_funct_list', 'empty' ]],
            3: [[ 'close_single_double_quotes', 'str_int', 'close_triple_quotes' ], [ 'close_dict', 'empty' ], [ 'close_funct_list', 'empty' ]],
            4: [[ 'close_single_double_quotes', 'str_int', 'close_triple_quotes' ], [ 'close_dict', 'empty' ], [ 'close_funct_list', 'empty' ], [ 'close_funct_list', 'empty' ]],
            5: [[ 'close_single_double_quotes', 'str_int', 'close_triple_quotes' ], [ 'close_dict', 'empty' ], [ 'close_funct_list', 'empty' ], [ 'close_funct_list', 'empty' ], ['close_if_loop', 'empty']],
    }
