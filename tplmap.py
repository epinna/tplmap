#!/usr/bin/env python
from utils.argparserhelper import CliParser
from core import checks
from utils.loggers import log

def main(args):
    
    arguments = {
        'url' : args.url
    }
    
    if args.post_data:
        arguments['post_data'] = args.post_data

    if args.headers:
        arguments['headers'] = args.headers
    
    checks.checkTemplateInjection(arguments)
    
if __name__ == '__main__':

    parser = CliParser(prog='tplmap')
    
    parser.add_argument('-d', '--data', action='append', dest='post_data', help = 'Post data')
    parser.add_argument('-H', '--header', action='append', dest='headers', help = 'Headers')
    parser.add_argument('url', help = 'Target URL')

    arguments = parser.parse_args()
    
    try:
        main(arguments)
    except (KeyboardInterrupt):
        log.info('Exiting.')
    except Exception as e:
        log.critical('Exiting: %s' % e)
        raise
