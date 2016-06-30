import unittest
import requests

class MakoTest(unittest.TestCase):
    
    def test_reflection(self):
        
        injection = '${7*7}'
        
        r = requests.post('http://127.0.0.1:15001/reflect', data = 
            {
                'tpl': '', 
                'inj': injection
            })
            
        self.assertEqual(r.text, '49')