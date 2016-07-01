import requests
from utils.loggers import log


class Channel:
    
    def __init__(self, url):
        
        self.url = url
        
        if '*' not in self.url:
            log.warn("no GET or parameter(s) found for testing ")
        
    def req(self, injection):
        return requests.get(self.url.replace('*', injection)).text