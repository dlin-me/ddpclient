from .selector import Selector
import datetime


class UserListClientSelector(Selector):
    def __init__(self):
        super(UserListClientSelector, self).__init__()

    def from_date_range(self, min_date=None, max_date=None):

        if min_date is None:
            min_date = datetime.date(1990, 1, 1)

        if max_date is None:
            max_date = datetime.date(2038, 1, 1)

        self.selector_data['dateRange'] = ('DateRange',
                                           {'min':
                                            ('Date', {'year': min_date.year,
                                                      'month': min_date.month,
                                                      'day': min_date.day}),
                                            'max':
                                            ('Date', {'year': max_date.year,
                                                      'month': max_date.month,
                                                      'day': max_date.day})})

        return self
