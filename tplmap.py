#!/usr/bin/env python
from utils import cliparser
from core import checks
from core.channel import Channel
from utils.loggers import log

def main():
    
    args = vars(cliparser.options)
    
    if not args.get('url'):
        cliparser.parser.error('URL is required. Run with -h for help.')
    
    checks.check_template_injection(Channel(args))
    
if __name__ == '__main__':

    try:
        main()
    except (KeyboardInterrupt):
        log.info('Exiting.')
    except Exception as e:
        log.critical('Exiting: %s' % e)
        raise
