# Shared closures

close_single_duble_quotes = [ '1\'', '1"' ]
integer = [ '1' ]
string = [ '"1"' ]
close_dict = [ '}', ':1}' ]
close_function = [ ')' ]
close_list = [ ']' ]
empty = [ '' ]

# Python triple quotes and if and for loop termination.
close_triple_quotes = [ '1"""' ]
if_loops = [ ':' ]

# Javascript needs this to bypass assignations
var = [ 'a' ]

# Java needs booleans to bypass conditions and iterable objects
true_var = [ 'true' ]
iterable_var = [ '[1]' ]