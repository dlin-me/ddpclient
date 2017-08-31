from .user_list_client_selector import UserListClientSelector
from .user_list_selector import UserListSelector
from .client import Client
from .auth import Auth
from .operation import Operation
import sys


def authorize_url():
    """Print the url for authorizing access to DDP."""
    if len(sys.argv) != 3:
        print("usage: ddp_authorize_url [client_id client_secret]")
    else:
        client_id = sys.argv[1]
        client_secret = sys.argv[2]
        print(Auth().authorize_url(client_id=client_id,
                                   client_secret=client_secret))


def authorize():
    """Authorize access by entering a authorize code."""
    if len(sys.argv) != 4:
        print("usage: ddp_authorize [client_id client_secret auth_code]")
    else:
        client_id = sys.argv[1]
        client_secret = sys.argv[2]
        authorize_code = sys.argv[3]

        print(Auth().authorize(client_id=client_id,
                               client_secret=client_secret,
                               auth_code=authorize_code).to_json())
