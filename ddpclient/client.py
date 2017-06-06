from suds.client import Client as SudsClient
from . import UserListClientSelector, UserListSelector
from operation import Operation
import os
import httplib2

USER_AGENT = 'DDP API Call'
USER_LIST_SERVICE_WSDL_URL = 'https://ddp.googleapis.com/api/ddp/provider/v201609/UserListService?wsdl'
USER_LIST_CLIENT_SERVICE_WSDL_URL = 'https://ddp.googleapis.com/api/ddp/provider/v201609/UserListClientService?wsdl'


class Client(object):

    soap_clients = {}

    def __init__(self, credentials=None, client_customer_id=None):

        if credentials.access_token_expired or credentials.access_token is None:
            http = httplib2.Http()
            credentials.refresh(http)

        self.credentials = credentials
        self.client_customer_id = os.getenv('DDP_CLIENT_CUSTOMER_ID',
                                            client_customer_id)
        self.user_list_service_soap_client = self._create_soap_client(
            USER_LIST_SERVICE_WSDL_URL)

        self.user_list_client_service_soap_client = self._create_soap_client(
            USER_LIST_CLIENT_SERVICE_WSDL_URL)

    def _create_soap_client(self, url):
        soap_client = SudsClient(url)

        # set http headers
        http_headers = {}
        self.credentials.apply(http_headers)

        soap_client.set_options(headers=http_headers)

        # set soap headers
        soap_headers = soap_client.factory.create('SoapHeader')
        soap_headers.clientCustomerId = self.client_customer_id
        soap_headers.userAgent = USER_AGENT
        soap_client.set_options(soapheaders=soap_headers)

        # https://fedorahosted.org/suds/wiki/TipsAndTricks#TypesNamesContaining
        soap_client.factory.separator('/')

        return soap_client

    def get(self, selector):
        soap_client = None

        if type(selector) is UserListSelector:
            soap_client = self.user_list_service_soap_client
        elif type(selector) is UserListClientSelector:
            soap_client = self.user_list_client_service_soap_client

        if soap_client is not None:
            return soap_client.service.get(selector.build(soap_client))

        return None

    def create_empty_user_list(self, is_logical=False):
        type_name = 'LogicalUserList' if is_logical else 'BasicUserList'
        return self.user_list_service_soap_client.factory.create(type_name)

    def create_empty_user_list_client(self, is_logical=False):
        return self.user_list_client_service_soap_client.factory.create(
            'UserListClient')

    def add(self, entity):
        soap_client = self._parse_entity_for_soap_client(entity)
        operation = self._parse_entity_for_operation(entity)
        return soap_client.service.mutate(operation.add(entity).build(
            soap_client))

    def set(self, entity):
        soap_client = self._parse_entity_for_soap_client(entity)
        operation = self._parse_entity_for_operation(entity)
        return soap_client.service.mutate(operation.set(entity).build(
            soap_client))

    def remove(self, entity):
        soap_client = self._parse_entity_for_soap_client(entity)
        operation = self._parse_entity_for_operation(entity)
        return soap_client.service.mutate(operation.remove(entity).build(
            soap_client))

    def _parse_entity_for_soap_client(self, entity):
        soap_client = None

        if hasattr(entity, 'UserList.Type'):
            soap_client = self.user_list_service_soap_client
        elif hasattr(entity, 'clientId') and hasattr(entity, 'userListId'):
            soap_client = self.user_list_client_service_soap_client

        return soap_client

    def _parse_entity_for_operation(self, entity):
        operation = None

        if hasattr(entity, 'UserList.Type'):
            operation = Operation('UserListOperation')
        elif hasattr(entity, 'clientId') and hasattr(entity, 'userListId'):
            operation = Operation('UserListClientOperation')

        return operation
