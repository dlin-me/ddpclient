from soap_entity import SoapEntity


class Operation(SoapEntity):
    def __init__(self, _type):
        self.operation_data = {}
        self.operation_type = _type

    def build(self, soap_client):
        return self.build_type(soap_client,
                               (self.operation_type, self.operation_data))

    def add(self, operand):
        self.operation_data['operator'] = ('Operator', 'ADD')
        self.operation_data['operand'] = operand
        return self

    def remove(self, operand):
        self.operation_data['operator'] = ('Operator', 'REMOVE')
        self.operation_data['operand'] = operand
        return self

    def set(self, operand):
        self.operation_data['operator'] = ('Operator', 'SET')
        self.operation_data['operand'] = operand
        return self
