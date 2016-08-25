import requests
from utils.loggers import log
import urlparse
from copy import deepcopy

class Channel:

    def __init__(self, args):

        self.args = args
        
        # Consider # as part of the query string, end encode \n
        self.url = self.args.get('url').replace('#', '%23').replace('\\n', '%0A')

        self.base_url = self.url.split("?")[0] if '?' in self.url else self.url

        self.tag = self.args.get('injection_tag')

        self.data = {}

        self.injs = []
        self.inj_idx = 0

        self.get_params = {}
        self.post_params = {}
        self.header_params = {}

        self._parse_get()
        self._parse_post()
        self._parse_header()
        self._parse_method()
        
        if not self.injs:
            # TODO: this will start discovery on every parameter
            log.error("No injection points found, use '%s' in URL, post data or headers." % self.tag)

    def _parse_method(self):

        if self.args.get('request'):
            self.http_method = self.args.get('request')
        elif self.post_params:
            self.http_method = 'POST'
        else:
            self.http_method = 'GET'

    def _parse_header(self):
        
        for param_value in self.args.get('headers', []):

            if ':' not in param_value:
                continue

            param, value = param_value.split(':')
            param = param.strip()
            value = value.strip()

            self.header_params[param] = value

            if self.tag in param:
                self.injs.append({
                    'field' : 'header',
                    'part' : 'param',
                    'param' : param
                })
            if self.tag in value:
                self.injs.append({
                    'field' : 'header',
                    'part' : 'value',
                    'value': value,
                    'param' : param
                })
            
                
        # Set user agent if not set already
        user_agent = self.args.get('user_agent')
        if not user_agent:
            user_agent = 'tplmap/%s' % self.args.get('version')
            
        if not 'user-agent' in [ p.lower() for p in self.header_params.keys() ]:
            self.header_params['User-Agent'] = user_agent

    def _parse_post(self):

        if self.args.get('data'):

            params_dict_list = urlparse.parse_qs(self.args.get('data'))

            for param, value_list in params_dict_list.items():

                self.post_params[param] = value_list
                
                if self.tag in param:
                    self.injs.append({
                        'field' : 'POST',
                        'part' : 'param',
                        'param' : param,
                    })
                
                for idx, value in enumerate(value_list):
                    if self.tag in value:
                        self.injs.append({
                            'field' : 'POST',
                            'part' : 'value',
                            'value' : value,
                            'param' : param,
                            'idx' : idx
                        })  
            
    def _parse_get(self):

        params_dict_list = urlparse.parse_qs(urlparse.urlsplit(self.url).query)

        for param, value_list in params_dict_list.items():

            self.get_params[param] = value_list
            
            if self.tag in param:
                self.injs.append({
                    'field' : 'GET',
                    'part' : 'param',
                    'param': param
                })
            
            for idx, value in enumerate(value_list):
                if self.tag in value:
                    self.injs.append({
                        'field' : 'GET',
                        'part': 'value',
                        'param': param,
                        'value' : value,
                        'idx' : idx
                    })                
            
    def req(self, injection):

        get_params = deepcopy(self.get_params)
        post_params = deepcopy(self.post_params)
        header_params = deepcopy(self.header_params)
        
        # Pick current injection by index
        inj = deepcopy(self.injs[self.inj_idx])
        
        if inj['field'] == 'POST':
        
            if inj.get('part') == 'param':
                # Inject injection within param
                old_value = post_params[inj.get('param')]
                del post_params[inj.get('param')]
                
                new_param = inj.get('param').replace(self.tag, injection)
                post_params[new_param] = old_value
                
            if inj.get('part') == 'value':
                # If injection in value, replace value by index    
                post_params[inj.get('param')][inj.get('idx')] = post_params[inj.get('param')][inj.get('idx')].replace(self.tag, injection)
                

        elif inj['field'] == 'GET':
                
            if inj.get('part') == 'param':
                # If injection replaces param, save the value 
                # with a new param
                old_value = get_params[inj.get('param')]
                del get_params[inj.get('param')]
                
                new_param = inj.get('param').replace(self.tag, injection)
                get_params[new_param] = old_value
                
            if inj.get('part') == 'value':
                # If injection in value, inject value in the correct index    
                get_params[inj.get('param')][inj.get('idx')] = get_params[inj.get('param')][inj.get('idx')].replace(self.tag, injection)
                
                
        elif inj['field'] == 'header':
                
            if inj.get('part') == 'param':
                # If injection replaces param, save the value 
                # with a new param
                old_value = get_params[inj.get('param')]
                del header_params[inj.get('param')]

                new_param = inj.get('param').replace(self.tag, injection)
                header_params[new_param] = old_value                
                            
            if inj.get('part') == 'value':
                # If injection in value, replace value by index    
                header_params[inj.get('param')] = header_params[inj.get('param')].replace(self.tag, injection)

        result = requests.request(
            method = self.http_method,
            url = self.base_url,
            params = get_params,
            data = post_params,
            headers = header_params
            ).text

        log.debug('\n> """%s"""\n< """%s"""' % (injection, result) )

        return result
