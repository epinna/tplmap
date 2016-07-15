closure_close_single_duble_quotes = [ '1\'', '1"' ]
closure_integer = [ '1' ]
closure_string = [ '"1"' ]
closure_close_dict = [ '}', ':1}' ]
closure_close_function = [ ')' ]
closure_close_list = [ ']' ]
closure_empty = [ '' ]

# Python triple quotes and if and for loop termination.
closure_close_triple_quotes = [ '1"""' ]
closure_if_loops = [ ':' ]

# Javascript needs this to bypass assignations
closure_var = [ 'a' ]

# Java needs booleans to bypass conditions and iterable objects
true_var = [ 'true' ]
iterable_var = [ '[1]' ]

python_ctx_closures = {
        1: [
            closure_close_single_duble_quotes + closure_integer,
            closure_close_function + closure_empty
        ],
        2: [
            closure_close_single_duble_quotes + closure_integer + closure_string,
            closure_close_function + closure_empty
        ],
        3: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_close_triple_quotes,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        4: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_close_triple_quotes,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        5: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_close_triple_quotes,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty,
            closure_close_function + closure_close_list + closure_empty,
            closure_if_loops + closure_empty
        ],
}

javascript_ctx_closures = {
        1: [
            closure_close_single_duble_quotes + closure_integer,
            closure_close_function + closure_empty
        ],
        2: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_empty
        ],
        3: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        4: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        5: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty,
            closure_close_function + closure_close_list + closure_empty,
        ],
}

php_ctx_closures = {
        1: [
            closure_close_single_duble_quotes + closure_integer,
            closure_close_function + closure_empty
        ],
        2: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_empty
        ],
        3: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        4: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        5: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty,
            closure_close_function + closure_close_list + closure_empty,
        ]
}

java_ctx_closures = {
        1: [
            closure_close_single_duble_quotes + closure_integer,
            closure_close_function + closure_empty
        ],
        2: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var + true_var,
            closure_close_function + closure_empty
        ],
        3: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var  + true_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        4: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var + true_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty
        ],
        5: [
            closure_close_single_duble_quotes + closure_integer + closure_string + closure_var + true_var + iterable_var,
            closure_close_function + closure_close_list + closure_close_dict + closure_empty,
            closure_close_function + closure_close_list + closure_empty,
        ]
}