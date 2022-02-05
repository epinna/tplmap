from optparse import OptionGroup
from optparse import OptionParser

import os
import sys

_ = os.path.normpath(sys.argv[0])

banner = """Tplmap %s
    Automatic Server-Side Template Injection Detection and Exploitation Tool
"""
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
                dest="data",
                help="Data string to be sent through POST. It must be as query string: param1=value1&param2=value2.",
                )

request.add_option("-H","--headers",
                action="append",
                dest="headers",
                help="Extra headers (e.g. 'Header1: Value1'). Use multiple times to add new headers.",
                default=[])

request.add_option("-c","--cookie",
                action="append",
                dest="cookies",
                help="Cookies (e.g. 'Field1=Value1'). Use multiple times to add new cookies.",
                default=[])
                
target.add_option("-X","--request",
                action="store",
                dest="request",
                help="Force usage of given HTTP method (e.g. PUT).")

request.add_option("-A","--user-agent",
                dest="user_agent",
                help="HTTP User-Agent header value."
                )
request.add_option("--proxy",
                dest="proxy",
                help="Use a proxy to connect to the target URL"
                )

# Detection options
detection = OptionGroup(parser, "Detection" , "These options can be used to customize the detection phase.")

detection.add_option("--level",
                    dest="level",
                    type="int",
                    default=0,
                    help="Level of code context escape to perform (1-5, Default: 1).")

detection.add_option("-e", "--engine",
                    dest="engine",
                    help="Force back-end template engine to this value.")

detection.add_option("-t", "--technique",
                    dest="technique",
                    help="Techniques R(endered) T(ime-based blind). Default: RT.",
                    default="RT")

# Template inspection options
tplcmd = OptionGroup(parser, "Template inspection", "These "
                       "options can be used to inspect the "
                       "template engine.")

tplcmd.add_option("--tpl-shell", dest="tpl_shell",
                    action="store_true",
                    help="Prompt for an interactive shell "
                         "on the template engine.")

tplcmd.add_option("--tpl-code", dest="tpl_code",
                    help="Inject code in the template engine.")

# OS access options
oscmd = OptionGroup(parser, "Operating system access", "These "
                       "options can be used to access the underlying "
                       "operating system.")

oscmd.add_option("--os-cmd", dest="os_cmd",
                    help="Execute an operating system command.")

oscmd.add_option("--os-shell", dest="os_shell",
                    action="store_true",
                    help="Prompt for an interactive operating "
                         "system shell.")

oscmd.add_option("--upload", dest="upload",
                    help="Upload LOCAL to REMOTE files.",
                    nargs=2)

oscmd.add_option("--force-overwrite", dest="force_overwrite",
                    action="store_true",
                    help="Force file overwrite when uploading.")

oscmd.add_option("--download", dest="download",
                    help="Download REMOTE to LOCAL files.",
                    nargs=2)

oscmd.add_option("--bind-shell", dest="bind_shell",
                    nargs=1,
                    type=int,
                    help="Spawn a system shell on a TCP PORT of the target and connect to it.")

oscmd.add_option("--reverse-shell", dest="reverse_shell",
                    nargs=2,
                    help="Run a system shell and back-connect to local HOST PORT.")

# OS access options
general = OptionGroup(parser, "General", "These "
                       "options can be used to set some general working parameters.")

general.add_option("--force-level", dest="force_level",
                    help="Force a LEVEL and CLEVEL to test.",
                    nargs=2)

general.add_option("--injection-tag", dest="injection_tag",
                    help="Use string as injection tag (default '*').",
                    default='*')

parser.add_option_group(target)
parser.add_option_group(request)
parser.add_option_group(detection)
parser.add_option_group(oscmd)
parser.add_option_group(tplcmd)
parser.add_option_group(general)

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
parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)

option = parser.get_option("-h")
option.help = option.help.capitalize().replace("Show this help message and exit", "Show help and exit.")

(options, args) = parser.parse_args()
