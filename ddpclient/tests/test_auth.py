from unittest import TestCase
from ddpclient import Auth

class TestAuth(TestCase):
    def test_authorize_url(self):
        auth = Auth()
        url = auth.authorize_url('client_id_foo', 'client_secret_bar')
        expected = 'https://accounts.google.com/o/oauth2/v2/auth?scope=https%3A%2F%2Fddp.googleapis.com%2Fapi%2Fddp&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&client_id=client_id_foo&access_type=offline'
         
        self.assertEqual(len(expected), len(url))
        
