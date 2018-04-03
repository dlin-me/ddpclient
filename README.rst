DDP API python client
---------------------

This is a python client library for the OAuth2 DDP API. Currently the following services are supported:

* UserListService
* UserListClientService


Installation
------------

::

    pip install ddpclient


Test
----

::

    python setup.py test

Deploy
----
Update the version and dependencies in `setup.py` and then:

::

    python setup.py sdist upload


Requirement
-----------

1. OAuth client ID and OAuth client secret

   DDP API uses OAuth 2.0 for authorization, to authorize the DDP API,
   you must first create a Client ID and a Client Secret. Visit the
   `Developer Console`_ to create a project and a OAuth client with
   credentials.

   You will use the client ID and secret to authorize DDP API.

2. AdWards Client `Customer ID`_

   A unique three-part number that’s assigned to each AdWords account,
   listed at the top of every page in your account.

   You can set it as an environment variable `DDP_CLIENT_CUSTOMER_ID`. Or you can pass the ID into the `Client` class constructor (details below).

Commands
--------

When installed, the DDP API client provide two command for authorizing
your application access to a DDP account.

These commands are provided to help quickly getting access to the DDP API to run the examples.
It stores crendentials in a file named ``.ddp_credentials``.
If you are using Flask or Django, consider using the ``oauth2client.contrib.flask_util`` and ``oauth2client.contrib.django_util``

Generate Authorize URL
^^^^^^^^^^^^^^^^^^^^^^

The ``ddp_authorize_url`` command expect the OAuth client id and client
secret as parameter and generate a URL for getting a AuthCode

::

    $ ddp_authorize_url
    usage: ddp_authorize_url [client_id client_secret]

Authorizing
^^^^^^^^^^^

The ``ddp_authorize`` command expect the OAuth client id, secrete and
the AuthCode obtained by using the ``ddp_authorize_url`` URL

::

    $ ddp_authorize
    usage: ddp_authorize [client_id client_secret auth_code]

Once this is done, a file ``.ddp_credentials`` is created and store the
resulting redentials. The credentials from this file will be used from
then on.

Usage
-----

Get UserList example:
^^^^^^^^^^^^^^^^^^^^^

::

    from ddpclient import UserListSelector, Client, Auth

    credentials = Auth().get_credentials()
    api_client = Client(credentials)
    selector = UserListSelector(). \
        select_fields('Id', 'Size'). \
        filter_by('Status', 'CLOSED'). \
        order_by('Id', True). \
        at_page(1, 3)
    response = api_client.get(selector)

    print response

    # (UserListPage){
    #    totalNumEntries = 108
    #    Page.Type = "UserListPage"
    #    entries[] =
    #       (BasicUserList){
    #          id = 978704062
    #          isReadOnly = False
    #          name = "Name one"
    #          size = 0
    #          sizeRange = "LESS_THAN_FIVE_HUNDRED"
    #          listType = "REMARKETING"
    #          UserList.Type = "BasicUserList"
    #       },
    #       (BasicUserList){
    #          id = 178703382
    #          isReadOnly = False
    #          name = "Name two"
    #          size = 0
    #          sizeRange = "LESS_THAN_FIVE_HUNDRED"
    #          listType = "REMARKETING"
    #          UserList.Type = "BasicUserList"
    #       },
    #       (BasicUserList){
    #          id = 138700763
    #          isReadOnly = False
    #          name = "Name three"
    #          size = 0
    #          sizeRange = "LESS_THAN_FIVE_HUNDRED"
    #          listType = "REMARKETING"
    #          UserList.Type = "BasicUserList"
    #       },
    #  }


Add UserList example:
^^^^^^^^^^^^^^^^^^^^^

::

    from ddpclient import UserListSelector, Client, Auth

    credentials = Auth().get_credentials()
    api_client = Client(credentials)

    new_user_list = api_client.create_empty_user_list()
    new_user_list.name = 'TEST'
    new_user_list.description = 'TEST Description'
    new_user_list.status = 'CLOSED'
    new_user_list.integrationCode = '123'
    new_user_list.accountUserListStatus = 'INACTIVE'

    response = api_client.add(new_user_list)

    print response


    # (UserListReturnValue){
    #    ListReturnValue.Type = "UserListReturnValue"
    #    value[] =
    #       (BasicUserList){
    #          id = 12345678
    #          isReadOnly = False
    #          name = "TEST"
    #          description = "TEST Description"
    #          status = "CLOSED"
    #          integrationCode = "123"
    #          accessReason = "OWNED"
    #          accountUserListStatus = "INACTIVE"
    #          membershipLifeSpan = 30
    #          listType = "REMARKETING"
    #          isEligibleForSearch = True
    #          isEligibleForDisplay = True
    #          UserList.Type = "BasicUserList"
    #       },
    #  }


Update UserList example:
^^^^^^^^^^^^^^^^^^^^^^^^

::

    from ddpclient import UserListSelector, Client, Auth

    credentials = Auth().get_credentials()
    api_client = Client(credentials)

    new_user_list = api_client.create_empty_user_list()
    new_user_list.id = 12345678
    new_user_list.description = 'TEST Description'

    response = api_client.set(new_user_list)

    print response

    # (UserListReturnValue){
    #    ListReturnValue.Type = "UserListReturnValue"
    #    value[] =
    #       (BasicUserList){
    #          id = 12345678
    #          isReadOnly = False
    #          name = "TEST Updated Name"
    #          description = "TEST Description"
    #          status = "CLOSED"
    #          integrationCode = "123"
    #          accessReason = "OWNED"
    #          accountUserListStatus = "INACTIVE"
    #          membershipLifeSpan = 30
    #          listType = "REMARKETING"
    #          isEligibleForSearch = True
    #          isEligibleForDisplay = True
    #          UserList.Type = "BasicUserList"
    #       },
    #  }


Remove UserList example:
^^^^^^^^^^^^^^^^^^^^^^^^

::

    from ddpclient import UserListSelector, Client, Auth

    credentials = Auth().get_credentials()
    api_client = Client(credentials)

    new_user_list = api_client.create_empty_user_list()
    new_user_list.id = 395803975

    response = api_client.remove(new_user_list)

    print response

    # suds.WebFault: Server raised fault: '[OperatorError.OPERATOR_NOT_SUPPORTED @ operations[0]]'
    # Note: UserListService does not support deleting user list, this code servers as example of 'remove' operations



Classes
-------

``Auth``
^^^^^^^^

``Auth`` class can be used to generate URL (``authorize_url``) for user giving authorization:

::

    Auth().authorize_url(client_id, client_secret)



``Auth`` also accept a auth code and obtain credentials after user having visited the above URL and granted the authorization to you application.
The credentials object returned will be saved into a ``storage`` object.

::

    Auth().authorize(client_id, client_secret, auth_code)


When the ``authorize`` method is done, by default ``Auth`` save the credentials object ( ``oauth2client.client.OAuth2Credentials``)
into a file (``.ddp_credentials``) using ``oauth2client.file.Storage``. Once saved, this credential can be retrieved by:

::

    credentials = Auth().get_credentials()


Saving credentials into a file for later retrieval is very simple but does not work for environments like Heroku.
You might want to save the credentials object into a database so that the credentials can survive between deployments.
The ``Auth`` constructor can accept a custom storage object with ``put`` and ``get`` methods defined.
Using custom storage object can save/retrieve credentials object into/from a database, for example.

::

    storage = MyDBStorage()
    auth = Auth(storage)

    auth.authorize(client_id, client_secret, auth_code)
    credentials = auth.get_credentials()


``Client``
^^^^^^^^^^

``Client`` manages SOAP services. It requires an ``oauth2client.client.OAuth2Credentials`` object ( most likely retrieved by ``Auth``)
to its constructor. ``Client`` then use the crendentials details to make SOAP API calls to available services (``UserListService`` and ``UserListClientService``)

A client customer id is also required to set the SOAP header in every request. You can provide it via an environment variable ``DDP_CLIENT_CUSTOMER_ID`` or pass it
explicitly to the constructor.


::

    credentials = Auth().get_credentials()
    client_customer_id = '123-123-1234'
    api_service = Client(credentials, client_customer_id).user_list_service_soap_client


``UserListSelector`` and ``UserListClientSelector``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These two selector classes are provided to specified entities to retrieve. They share the same interface. Example


::

    from ddpclient import UserListClientSelector, Client, Auth
    import datetime

    selector = UserListClientSelector(). \
        select_fields('ClientCustomerName', 'UserListId'). \
        filter_by('Status', 'ACTIVE'). \
        order_by('UserListId'). \
        order_by('ClientCustomerName', desc=True). \
        from_date_range(datetime.date(2016, 1, 1), datetime.date(2016, 1, 7)). \
        at_page(1, 3)

.. _Developer Console: http://
.. _Customer ID: https://support.google.com/adwords/answer/29198?hl=en-AU
