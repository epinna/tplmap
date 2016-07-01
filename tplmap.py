#!/usr/bin/env python
from utils.argparserhelper import CliParser
from core import checks
from utils.loggers import log

def main(args):
    
    checks.checkTemplateInjection({
        'url' : args.url
    })
    
    
if __name__ == '__main__':

    parser = CliParser(prog='tplmap')
    
    parser.add_argument('url', nargs = 1, help = 'Target URL')

    arguments = parser.parse_args()

    try:
        main(arguments)
    except (KeyboardInterrupt):
        log.info('Exiting.')
    except Exception as e:
        log.critical('Exiting: %s' % e)
        raise
