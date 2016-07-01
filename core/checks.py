from plugins.engines.mako import Mako
from core.http import Channel
from utils.loggers import log

def checkTemplateInjection(args):
    
    channel = Channel(url = args["url"][0])
    mako = Mako(channel)