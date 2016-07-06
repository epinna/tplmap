from optparse import OptionGroup
from optparse import OptionParser

import os
import sys

_ = os.path.normpath(sys.argv[0])

usage = "python %prog [options]"
epilog = """
Example:

 ./tplmap -u 'http://www.target.com/page.php?id=1*'
 
"""

class MyParser(OptionParser):
    def format_epilog(self, formatter):
        return self.epilog

parser = MyParser(usage=usage, epilog=epilog)

# Target options
target = OptionGroup(parser, "Target", "These options have to be provided, to define the target URL. ")

target.add_option("-u","--url",
                action="store",
                dest="url",
                help="Target URL.")

# Request options
request = OptionGroup(parser, "Request", "These options have how to connect and where to inject to the target URL.")

request.add_option("-d","--data", 
                action="store",
                dest="data",
                help="Data string to be sent through POST.",
                default=[])

request.add_option("-H","--headers",
                action="store",
                dest="headers",
                help="Extra headers (e.g. 'Header1:Value1\\nHeader2:Value2').",
                default=[])

target.add_option("-X","--request",
                action="store",
                dest="request",
                help="Force usage of given HTTP method (e.g. PUT)")

# Detection options
detection = OptionGroup(parser, "Detection" , "These options can be used to customize the detection phase.")

detection.add_option("--level", 
                    dest="level", 
                    type="int",
                    default=1,
                    help="Level of tests to perform (1-5, Default: 1).")


parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(detection)

"""
Dirty hack from sqlmap [1], to display longer options without breaking into two lines.
[1] https://github.com/sqlmapproject/sqlmap/blob/fdc8e664dff305aca19acf143c7767b9a7626881/lib/parse/cmdline.py
"""
def _(self, *args):
    _ = parser.formatter._format_option_strings(*args)
    if len(_) > 18:
        _ = ("%%.%ds.." % (18 - parser.formatter.indent_increment)) % _
    return _

parser.formatter._format_option_strings = parser.formatter.format_option_strings
parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

option = parser.get_option("-h")
option.help = option.help.capitalize().replace("Show this help message and exit", "Show help and exit.")

(options, args) = parser.parse_args()
