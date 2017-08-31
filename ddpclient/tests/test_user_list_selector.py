from unittest import TestCase
from ddpclient import UserListSelector, Client
from oauth2client.client import OAuth2Credentials
import datetime


class TestUserListSelector(TestCase):
    def setUp(self):
        self.client = Client(OAuth2Credentials('token', 'clientid', 'secret',
                                               'rtoken', datetime.datetime(
                                                   2038, 1, 1), 'uri', 'ua'))
        self.selector = UserListSelector()

    def test_select_fields(self):
        selector = self.selector.select_fields(
            'Id', 'Name',
            'Description').build(self.client.user_list_service_soap_client)
        
        self.assertListEqual(['Id', 'Name', 'Description'], selector.fields)
        
    def test_filter_by(self):
        selector = self.selector.filter_by('Name', 'Test').filter_by(
            'Id', 100, '>=').build(self.client.user_list_service_soap_client)

        predicate = selector.predicates[0]

        self.assertEqual('Name', predicate.field)
        self.assertEqual('EQUALS', predicate.operator)
        self.assertEqual('Test', predicate.values)

        predicate = selector.predicates[1]

        self.assertEqual('Id', predicate.field)
        self.assertEqual('GREATER_THAN_EQUALS', predicate.operator)
        self.assertEqual(100, predicate.values)

    def test_order_by(self):
        selector = self.selector.order_by('Id').order_by(
            'Name', desc=True).build(self.client.user_list_service_soap_client)

        self.assertEqual('Id', selector.ordering[0].field)
        self.assertEqual('ASCENDING', selector.ordering[0].sortOrder)
        self.assertEqual('Name', selector.ordering[1].field)
        self.assertEqual('DESCENDING', selector.ordering[1].sortOrder)

    def test_from_date_range(self):
        selector = self.selector.from_date_range(
            datetime.date(2011, 5, 6), datetime.date(
                2016, 3, 4)).build(self.client.user_list_service_soap_client)

        self.assertEqual('20110506', selector.dateRange.min)
        self.assertEqual('20160304', selector.dateRange.max)

    def test_at_page(self):
        selector = self.selector.at_page(
            2, 12).build(self.client.user_list_service_soap_client)

        self.assertEqual(2, selector.paging.startIndex)
        self.assertEqual(12, selector.paging.numberResults)
