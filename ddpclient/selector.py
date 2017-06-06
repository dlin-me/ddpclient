import datetime
from soap_entity import SoapEntity


class Selector(SoapEntity):
    def __init__(self):
        self.selector_data = {'fields': [], 'predicates': [], 'ordering': []}

    def build(self, soap_client):
        return self.build_type(soap_client, ('Selector', self.selector_data))

    def select_fields(self, *args):
        self.selector_data['fields'] = list(args)
        return self

    # filter criteria
    def filter_by(self, field, values, operator='=='):
        self.selector_data['predicates'].append(
            ('Predicate', {'field': field,
                           'operator':
                           self._create_predicate_operator(operator),
                           'values': values}))

        return self

    def order_by(self, field, desc=False):
        """sorting a field by either 'ASCENDING' or 'DESCENDING' order."""

        sort_order = ('SortOrder', 'DESCENDING' if desc else 'ASCENDING')
        self.selector_data['ordering'].append(('OrderBy', {'field': field,
                                                           'sortOrder':
                                                           sort_order}))

        return self

    def at_page(self, start_index=0, page_size=100):
        self.selector_data['paging'] = ('Paging', {'startIndex': start_index,
                                                   'numberResults': page_size})

        return self

    def _create_predicate_operator(self, short_operator_name):
        operator_map = {'!=': 'NOT_EQUALS',
                         '<>': 'NOT_EQUALS',
                         '==': 'EQUALS',
                         '>': 'GREATER_THAN',
                         '>=': 'GREATER_THAN_EQUALS',
                         '<': 'LESS_THAN',
                         '<=': 'LESS_THAN_EQUALS',
                         '[]': 'IN',
                         '][': 'NOT_IN'}

        match_operator = operator_map[
            short_operator_name] if operator_map.has_key(
                short_operator_name) else short_operator_name

        return 'Predicate.Operator', match_operator
