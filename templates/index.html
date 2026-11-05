"""A separate application that checks a password through HTTP, without the UI.

First create a credential in the browser. Then run:
    python client.py
    python client.py https://YOUR-SERVICE.onrender.com
"""

import json
import sys
from getpass import getpass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def check_password(base_url, username, password):
    payload = json.dumps({"username": username, "password": password}).encode()
    request = Request(
        base_url.rstrip("/") + "/api/passwords/check",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=90) as response:
        return json.load(response)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    try:
        result = check_password(url, input("Username: "), getpass("Password: "))
        print("Password matches." if result["valid"] else "Username or password is incorrect.")
    except (HTTPError, URLError, TimeoutError):
        print("Could not check the password. Check the service URL and try again.")
        raise SystemExit(1)
