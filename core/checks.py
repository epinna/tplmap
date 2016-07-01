from plugins.engines.mako import Mako
from plugins.engines.jinja2 import Jinja2
from core.http import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(url = args["url"][0])
    mako = Mako(channel)
    
    if not mako.state['reflection']:
        return
        
    jinja2 = Jinja2(channel)