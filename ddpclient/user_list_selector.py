from selector import Selector
import datetime


class UserListSelector(Selector):
    def __init__(self):
        super(UserListSelector, self).__init__()

    def from_date_range(self, min_date=None, max_date=None):

        if min_date is None:
            min_date = datetime.date(1990, 1, 1)

        if max_date is None:
            max_date = datetime.date(2038, 1, 1)

        self.selector_data['dateRange'] = (
            'DateRange', {'min': min_date.strftime('%Y%m%d'),
                          'max': max_date.strftime('%Y%m%d')})

        return self
