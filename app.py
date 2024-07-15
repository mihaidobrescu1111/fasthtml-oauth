from fasthtml.common import *
from fasthtml.oauth import WebApplicationClient
from fasthtml.oauth import *
import string
import random
import httpx
import base64
import hashlib
import os

hf_state = None

app = FastHTMLWithLiveReload()
rt = app.route

base = "mihaidobrescu-fasthtml-docker.hf.space"

git_client_id = os.environ.get("GIT_CLIENT_ID")
git_client_secret = os.environ.get("GIT_CLIENT_SECRET")
git_redirect_uri = f"http://{base}/integrations/github/oauth2/callback"
git_client = GitHubAppClient(client_id=git_client_id, client_secret=git_client_secret, redirect_uri=git_redirect_uri)

google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
google_redirect_uri = f"http://{base}/integrations/google/oauth2/callback"
google_client = GoogleAppClient(client_id=google_client_id, redirect_uri=google_redirect_uri,
                                client_secret=google_client_secret)

hf_client_id = os.environ.get("HF_CLIENT_ID")
hf_client_secret = os.environ.get("HF_CLIENT_SECRET")
hf_redirect_uri = f"http://{base}/auth/callback"
hf_client = WebApplicationClient(client_id=hf_client_id, client_secret=hf_client_secret, redirect_uri=hf_redirect_uri)


@rt("/integrations/github/oauth2/callback")
def get(code: str = None):
    if not code:
        return Titled("Error", "No code provided", A("Home", href='/'))
    git_client.parse_response(code)
    user_info = git_client.get_info()
    # print(user_info)
    return Titled("Logged In", f"Hello, {user_info.get('login')}!", A("Home", href='/'))


@rt("/integrations/google/oauth2/callback")
def get(code: str = None):
    if not code:
        return Titled("Error", "No code provided", A("Home", href='/'))
    google_client.parse_response(code)
    user_info = google_client.get_info()
    # print(user_info)
    return Titled("Logged In", f"Hello, {user_info.get('name')}!", A("Home", href='/'))


@rt("/auth/callback")
def get(code: str = None, state: str = None):
    if state != hf_state:
        return Titled("State error")
    basic_auth_str = f"{hf_client_id}:{hf_client_secret}"
    basic_auth_bytes = basic_auth_str.encode("ascii")
    basic_auth_base64 = base64.b64encode(basic_auth_bytes).decode("ascii")
    headers = {
        "Authorization": f"Basic {basic_auth_base64}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "client_id": hf_client_id,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": hf_redirect_uri
    }

    token_url = "https://huggingface.co/oauth/token"
    info_url = "https://huggingface.co/api/whoami-v2"

    response = httpx.post(token_url, headers=headers, data=data)
    if response.status_code == 200:
        tokens = response.json()
        token = tokens.get("access_token")
        headers = {"Authorization": f"Bearer {token}",
                   }
        res = httpx.get(info_url, headers=headers)
        name = res.json().get("name")
        return Titled("Logged In", f"Hello, {name}!", A("Home", href='/'))
    else:
        return Titled("Error", A("Home", href='/'))


@rt("/")
def get():
    global hf_state
    git_login_link = git_client.prepare_request_uri(git_client.base_url, git_client.redirect_uri, scope='user')

    google_login_link = google_client.prepare_request_uri(google_client.base_url, google_client.redirect_uri,
                                                          scope='https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid')

    hf_state = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    hf_login_link = f"https://huggingface.co/oauth/authorize?response_type=code&redirect_uri={hf_redirect_uri}&scope=openid%20profile&client_id={hf_client_id}&state={hf_state}"

    return Titled("Login", A("GitHub", href=git_login_link), A("Google", href=google_login_link),
                  A("HuggingFace", href=hf_login_link))
