from unittest import TestCase
from ddpclient import UserListClientSelector, Client
from oauth2client.client import OAuth2Credentials
import datetime


class TestUserListClientSelector(TestCase):
    def setUp(self):
        self.client = Client(OAuth2Credentials('token', 'clientid', 'secret',
                                               'rtoken', datetime.datetime(
                                                   2038, 1, 1), 'uri', 'ua'))
        self.selector = UserListClientSelector()


    # dateRange removed in v201702
    #def test_from_date_range(self):
    #    selector = self.selector.from_date_range(
    #        datetime.date(2011, 5, 6), datetime.date(
    #            2016, 3,
    #            4)).build(self.client.user_list_client_service_soap_client)

    #    self.assertEqual(2011, selector.dateRange.min.year)
    #    self.assertEqual(5, selector.dateRange.min.month)
    #    self.assertEqual(6, selector.dateRange.min.day)
    #    self.assertEqual(2016, selector.dateRange.max.year)
    #    self.assertEqual(3, selector.dateRange.max.month)
    #    self.assertEqual(4, selector.dateRange.max.day)
