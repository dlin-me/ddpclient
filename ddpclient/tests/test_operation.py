import datetime
from oauth2client.client import OAuth2Credentials
from unittest import TestCase

from ddpclient import Client, Operation


class TestOperation(TestCase):
    def setUp(self):
        self.client = Client(
            OAuth2Credentials('token',
                              'clientid',
                              'secret',
                              'rtoken',
                              datetime.datetime(2038, 1, 1),
                              'uri',
                              'ua')
        )

        self.operation = Operation('UserListOperation')

        self.user_list = self.client.create_empty_user_list()
        self.user_list.id = 123
        self.user_list.name = 'TEST'
        self.user_list.description = 'TEST Description'
        self.user_list.status = 'CLOSED'
        self.user_list.integrationCode = '123'
        self.user_list.accountUserListStatus = 'INACTIVE'
        self.user_list.membershipLifeSpan = 3

    def test_add_user_list(self):
        operation = self.operation.add(self.user_list).build(
            self.client.user_list_service_soap_client)

        self.assertEqual('ADD', operation.operator)
        self.assertEqual('TEST', operation.operand.name)

    def test_set_user_list(self):
        operation = self.operation.set(self.user_list).build(
            self.client.user_list_service_soap_client)

        self.assertEqual('SET', operation.operator)
        self.assertEqual('TEST', operation.operand.name)
        self.assertEqual(123, operation.operand.id)

    def test_remove_user_list(self):
        operation = self.operation.remove(self.user_list).build(
            self.client.user_list_service_soap_client)

        self.assertEqual('REMOVE', operation.operator)
        self.assertEqual('TEST', operation.operand.name)
        self.assertEqual(123, operation.operand.id)
