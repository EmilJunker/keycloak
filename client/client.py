import base64
import json
import os
from urllib.parse import quote

import jwt
import requests
from flask import Flask, redirect, request, session, url_for
from flask.json import jsonify
from requests_oauthlib import OAuth2Session

app = Flask(__name__)


# OAuth config information
client_id = "myclient"
client_secret = None
# authorization_base_url = "https://localhost:8443/auth/realms/simple/protocol/openid-connect/auth"
# token_url = "https://localhost:8443/auth/realms/simple/protocol/openid-connect/token"
# protected_url = "https://localhost:8443/auth/realms/simple/protocol/openid-connect/userinfo"
# logout_url = "https://localhost:8443/auth/realms/simple/protocol/openid-connect/logout"
# client_url = "http://localhost:5000"
# callback_url = "http://localhost:5000/callback"
authorization_base_url = "https://oai-pmh-test.basisit.de:8443/auth/realms/simple/protocol/openid-connect/auth"
token_url = "https://oai-pmh-test.basisit.de:8443/auth/realms/simple/protocol/openid-connect/token"
protected_url = "https://oai-pmh-test.basisit.de:8443/auth/realms/simple/protocol/openid-connect/userinfo"
logout_url = "https://oai-pmh-test.basisit.de:8443/auth/realms/simple/protocol/openid-connect/logout"
client_url = "http://oai-pmh-test.basisit.de:5000"
callback_url = "http://oai-pmh-test.basisit.de:5000/callback"


@app.route("/login")
def login():
    """Step 1: User authorization.

    Redirect the user (resource owner) to the identity provider (Keycloak).
    """
    oauth = OAuth2Session(client_id, redirect_uri=callback_url, scope="openid")
    authorization_url, state = oauth.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    return redirect(authorization_url)


# Step 2: User authorization, this happens on the identity provider.

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the identity provider to this
    callback URL. With the redirection comes an authorization code included in
    the URL. We will use that authorization code to obtain an access token.
    """
    oauth = OAuth2Session(client_id, redirect_uri=callback_url, state=session["oauth_state"])
    oauth_token = oauth.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url, verify=False)

    # Now we have an access token. The access token includes basic user info.
    # The user can use the access token to fetch protected resources. But before
    # we do that, we will verify the token.

    if verify_token(oauth_token.get("access_token")):
        # Save the token and then redirect the user to the home page.
        session["oauth_token"] = oauth_token
        return redirect(url_for(".home"))
    else:
        return "the token is invalid"


def verify_token(token):
    """ Step 4: Verifying the token.

    Verify the token using the issuer's public key. This happens on the client.
    """
    # Decode all three parts of the token (it is Base64 encoded).
    decoded_token = [
        base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))
        for d in token.split(".")
    ]
    header = json.loads(decoded_token[0])
    payload = json.loads(decoded_token[1])
    signature = decoded_token[2]

    # The issuer is encoded in the payload of the token.
    issuer_url = payload["iss"]
    public_key = requests.get(issuer_url, verify=False).json()["public_key"]
    key = "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"

    # If the token is valid, we can now decode it using the public key.
    try:
        decoded = jwt.decode(token, key, audience=payload["aud"], algorithms=header["alg"])
        session["user"] = payload["name"]
        return True
    except Exception as e:
        print(str(e))
        return False


@app.route("/")
def home():
    """Step 5: User authorization successful.

    Show a welcome message and display the token.
    """
    if not "oauth_token" in session:
        return redirect(url_for(".login"))
    if not verify_token(session['oauth_token'].get("access_token")):
        return redirect(url_for(".login"))

    user = session['user']
    token = session['oauth_token'].get("access_token")
    return """
    <h1>Welcome {}!</h1>
    <code style="overflow-wrap:anywhere">Your access token: <br/> {}</code>
    <p><a href="/profile">Profile</a></p>
    <p><a href="/logout">Logout</a></p>
    """.format(user, token)


@app.route("/profile", methods=["GET"])
def profile():
    """ Step 6: Fetching protected resources using the access token.

    Use the access token to fetch some information about the user from the
    identity provider.
    """
    if not "oauth_token" in session:
        return redirect(url_for(".login"))
    if not verify_token(session['oauth_token'].get("access_token")):
        return redirect(url_for(".login"))

    oauth = OAuth2Session(client_id, token=session["oauth_token"])
    return jsonify(oauth.get(protected_url, verify=False).json())


@app.route("/logout", methods=["GET"])
def logout():
    """ Step 7: Logout the user.

    End the session for the user and redirect back to the client base URL.
    """
    if not "oauth_token" in session:
        return redirect(url_for(".login"))
    session.clear()
    return redirect(f"{logout_url}?redirect_uri={quote(client_url)}")


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    app.secret_key = os.urandom(24)
    # app.run(debug=True)
    app.run(host="0.0.0.0", debug=True)
