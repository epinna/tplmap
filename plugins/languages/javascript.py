from core.plugin import Plugin

class Javascript(Plugin):

    closure_close_single_duble_quotes = [ '1\'', '1"' ]
    closure_integer = [ '1' ]
    closure_string = [ '"1"' ]
    closure_close_dict = [ '}', ':1}' ]
    closure_close_function = [ ')' ]
    closure_close_list = [ ']' ]
    closure_empty = [ '' ]

    code_context_closures = {
            1: [
                closure_close_single_duble_quotes + closure_integer,
                closure_close_function + closure_empty
            ],
            2: [
                closure_close_single_duble_quotes + closure_integer + closure_string,
                closure_close_function + closure_empty
            ],
            3: [
                closure_close_single_duble_quotes + closure_integer + closure_string,
                closure_close_function + closure_close_list + closure_close_dict + closure_empty
            ],
            4: [
                closure_close_single_duble_quotes + closure_integer + closure_string,
                closure_close_function + closure_close_list + closure_close_dict + closure_empty
            ],
            5: [
                closure_close_single_duble_quotes + closure_integer + closure_string,
                closure_close_function + closure_close_list + closure_close_dict + closure_empty,
                closure_close_function + closure_close_list + closure_empty,
            ],
    }
