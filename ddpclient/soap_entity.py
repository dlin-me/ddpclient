from six import iteritems

class SoapEntity(object):
    def build_type(self, soap_client, data):

        if type(data) is tuple:
            t, d = data
            type_obj = soap_client.factory.create(t)

            if type(d) is dict:
                for sub_k, sub_data in iteritems(d):
                    type_obj[sub_k] = self.build_type(soap_client, sub_data)

                return type_obj
            else:
                return type_obj[d]
        elif type(data) is list:

            return [self.build_type(soap_client, sub_data)
                    for sub_data in data]

        else:
            return data
