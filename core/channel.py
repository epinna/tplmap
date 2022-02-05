import requests
import urllib3
from utils.loggers import log
import sys

if sys.version_info.major > 2 :
    import urllib.parse as urlparse
else :
    import urlparse

from copy import deepcopy
import utils.config

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

        proxy = self.args.get('proxy')
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
        else:
            self.proxies = {}

        self.get_params = {}
        self.post_params = {}
        self.header_params = {}

        self._parse_url()
        self._parse_cookies()

        self._parse_get()
        self._parse_post()
        self._parse_header()
        
        # If there are not injection, inject
        # all the passed GET, POST, and Headers
        if not self.injs:

            self._parse_get(all_injectable = True)
            self._parse_post(all_injectable = True)
            self._parse_header(all_injectable = True)

        self._parse_method()
        
        # Disable requests warning in case of 
        # skipped SSL certificate check
        urllib3.disable_warnings()
        
    def _parse_method(self):

        if self.args.get('request'):
            self.http_method = self.args.get('request')
        elif self.post_params:
            self.http_method = 'POST'
        else:
            self.http_method = 'GET'

        
    def _parse_url(self):

        url_path = urlparse.urlparse(self.url).path

        if not self.tag in url_path:
            return
            
        url_path_base_index = self.url.find(url_path)
        
        for index in [ 
            i for i in range(url_path_base_index, url_path_base_index + len(url_path)) if self.url[i] == self.tag 
        ]:
            self.injs.append({
                'field' : 'URL',
                'param' : 'url',
                'position': url_path_base_index + index
            })
                

    def _parse_cookies(self):
        
        # Just add cookies as headers, to avoid duplicating
        # the parsing code. Concatenate to avoid headers with
        # the same key.
        
        cookies = self.args.get('cookies', [])
        
        if cookies:
            cookie_string = 'Cookie: %s' % ';'.join(cookies)
            
            if not self.args.get('headers'):
                self.args['headers'] = []
            self.args['headers'].append(cookie_string)

    def _parse_header(self, all_injectable = False):

        for param_value in self.args.get('headers', []):

            if ':' not in param_value:
                continue

            param, value = param_value.split(':', 1)
            param = param.strip()
            value = value.strip()

            self.header_params[param] = value

            if self.tag in param:
                self.injs.append({
                    'field' : 'Header',
                    'part' : 'param',
                    'param' : param
                })
                
            if self.tag in value or all_injectable:
                self.injs.append({
                    'field' : 'Header',
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

    def _parse_post(self, all_injectable = False):

        if self.args.get('data'):

            params_dict_list = urlparse.parse_qs(self.args.get('data'), keep_blank_values=True)

            for param, value_list in params_dict_list.items():

                self.post_params[param] = value_list
                
                if self.tag in param:
                    self.injs.append({
                        'field' : 'POST',
                        'part' : 'param',
                        'param' : param,
                    })
                
                for idx, value in enumerate(value_list):
                    if self.tag in value or all_injectable:
                        self.injs.append({
                            'field' : 'POST',
                            'part' : 'value',
                            'value' : value,
                            'param' : param,
                            'idx' : idx
                        })  
            
    def _parse_get(self, all_injectable = False):

        params_dict_list = urlparse.parse_qs(urlparse.urlsplit(self.url).query, keep_blank_values=True)

        for param, value_list in params_dict_list.items():

            self.get_params[param] = value_list
            
            if self.tag in param:
                self.injs.append({
                    'field' : 'GET',
                    'part' : 'param',
                    'param': param
                })
            
            for idx, value in enumerate(value_list):
                if self.tag in value or all_injectable:
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
        url_params = self.base_url
        
        # Pick current injection by index
        inj = deepcopy(self.injs[self.inj_idx])
        
        if inj['field'] == 'URL':
            
            position = inj['position']
            
            url_params = self.base_url[:position] + injection + self.base_url[position+1:]
        
        elif inj['field'] == 'POST':
        
            if inj.get('part') == 'param':
                # Inject injection within param
                old_value = post_params[inj.get('param')]
                del post_params[inj.get('param')]
                
                if self.tag in inj.get('param'):
                    new_param = inj.get('param').replace(self.tag, injection)
                else:
                    new_param = injection
                    
                post_params[new_param] = old_value
                
            if inj.get('part') == 'value':
                
                # If injection in value, replace value by index    
                if self.tag in post_params[inj.get('param')][inj.get('idx')]:
                    post_params[inj.get('param')][inj.get('idx')] = post_params[inj.get('param')][inj.get('idx')].replace(self.tag, injection)
                else:
                    post_params[inj.get('param')][inj.get('idx')] = injection

        elif inj['field'] == 'GET':
                
            if inj.get('part') == 'param':
                # If injection replaces param, save the value 
                # with a new param
                old_value = get_params[inj.get('param')]
                del get_params[inj.get('param')]
                
                if self.tag in inj.get('param'):
                    new_param = inj.get('param').replace(self.tag, injection)
                else:
                    new_param = injection
                    
                get_params[new_param] = old_value
                
            if inj.get('part') == 'value':
                # If injection in value, inject value in the correct index
                if self.tag in get_params[inj.get('param')][inj.get('idx')]:
                    get_params[inj.get('param')][inj.get('idx')] = get_params[inj.get('param')][inj.get('idx')].replace(self.tag, injection)
                else:
                    get_params[inj.get('param')][inj.get('idx')] = injection
                
        elif inj['field'] == 'Header':
            
            # Headers can't contain \r or \n, sanitize
            injection = injection.replace('\n', '').replace('\r', '')
                
            if inj.get('part') == 'param':
                # If injection replaces param, save the value 
                # with a new param
                old_value = get_params[inj.get('param')]
                del header_params[inj.get('param')]
                
                if self.tag in inj.get('param'):
                    new_param = inj.get('param').replace(self.tag, injection)
                else:
                    new_param = injection
                    
                header_params[new_param] = old_value                
                            
            if inj.get('part') == 'value':
                # If injection in value, replace value by index    
                
                if self.tag in header_params[inj.get('param')]:
                    header_params[inj.get('param')] = header_params[inj.get('param')].replace(self.tag, injection)
                else:
                    header_params[inj.get('param')] = injection
        
        if self.tag in self.base_url:
            log.debug('[URL] %s' % url_params)
        if get_params:
            log.debug('[GET] %s' % get_params)
        if post_params:
            log.debug('[POST] %s' % post_params)
        if len(header_params) > 1:
            log.debug('[HEDR] %s' % header_params)
        
        try:
            result = requests.request(
                method = self.http_method,
                url = url_params,
                params = get_params,
                data = post_params,
                headers = header_params,
                proxies = self.proxies,
                # By default, SSL check is skipped.
                # TODO: add a -k curl-like option to set this.
                verify = False
                ).text
        except requests.exceptions.ConnectionError as e:
            if e and e[0] and e[0][0] == 'Connection aborted.':
                log.info('Error: connection aborted, bad status line.')
                result = None
            else:
                raise

        if utils.config.log_response:
            log.debug("""< %s""" % (result) )

        return result

    def detected( self, technique, detail ):
        pass
