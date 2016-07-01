import argparse
import sys

SUPPRESS = argparse.SUPPRESS
msg_error = """
[+] tplmap 0.1
[!] Error: %s

[+] Check template injection

"""

class HelpParser(argparse.ArgumentParser):

    """
    Override `error` method of `argparse.ArgumentParser`
    in order to print the complete help on error.
    """

    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


class CliParser(argparse.ArgumentParser):

	def set_default_subparser(self, name, args=None):
	    """default subparser selection. Call after setup, just before parse_args()
	    name: is the name of the subparser to call by default
	    args: if set is the argument list handed to parse_args()

	    , tested with 2.7, 3.2, 3.3, 3.4
	    it works with 2.6 assuming argparse is installed
	    """
	    subparser_found = False
	    for arg in sys.argv[1:]:
    		if arg in ['-h', '--help']:
    		    break
	    else:
    		for x in self._subparsers._actions:
    		    if not isinstance(x, argparse._SubParsersAction):
    		        continue
    		    for sp_name in x._name_parser_map.keys():
    		        if sp_name in sys.argv[1:]:
    		            subparser_found = True
    		if not subparser_found:
    		    # insert default in first position, this implies no
    		    # global options without a sub_parsers specified
    		    if args is None:
    		        sys.argv.insert(1, name)
    		    else:
    		        args.insert(0, name)

	def error(self, message):
		sys.stderr.write(msg_error % (message))
		#self.print_help()
		sys.exit(2)
