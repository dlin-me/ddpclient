from unittest import TestCase
from ddpclient import Client
from oauth2client.client import OAuth2Credentials
import datetime


class TestClient(TestCase):
    def setUp(self):
        self.client = Client(OAuth2Credentials('token', 'clientid', 'secret',
                                               'rtoken', datetime.datetime(
                                                   2038, 1, 1), 'uri', 'ua'))

    def test_create_user_list_service(self):
        service = self.client.user_list_service_soap_client
        self.assertEqual(
            'https://ddp.googleapis.com/api/ddp/provider/v201705/UserListService?wsdl',
            service.wsdl.url)

    def test_create_user_list_client_service(self):
        service = self.client.user_list_client_service_soap_client
        self.assertEqual(
            'https://ddp.googleapis.com/api/ddp/provider/v201705/UserListClientService?wsdl',
            service.wsdl.url)
