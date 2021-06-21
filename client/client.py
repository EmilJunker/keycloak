import base64
import configparser
import json
import os
from datetime import datetime
from urllib.parse import quote

import requests
from flask import Flask, redirect, request, session, url_for, render_template
from flask.json import jsonify
from requests_oauthlib import OAuth2Session

app = Flask(__name__)


# OAuth config information
config = configparser.ConfigParser()
s = config.read("/workspaces/keycloak/client/config.cfg")

client_base_url = config["DEFAULT"]["client_base_url"]
client_id = config["oidc"]["client_id"]
client_uid = config["oidc"]["client_uid"]
authorization_base_url = config["oidc"]["authorization_base_url"]
logout_url = config["oidc"]["logout_url"]
token_url = config["oidc"]["token_url"]
login_callback_url = config["oidc"]["login_callback_url"]
token_callback_url = config["oidc"]["token_callback_url"]


@app.route("/")
def home():
    offline_session = {}
    offline_token = ""
    if "user_uid" in session:
        offline_sessions = get_keycloak_offline_sessions(config)
        if len(offline_sessions) != 0:
            session_start = int(offline_sessions[0]["start"]) / 1000
            session_accessed = int(offline_sessions[0]["lastAccess"])
            session_start_time = datetime.fromtimestamp(session_start).strftime("%Y-%m-%d %H:%M:%S")
            session_accessed_time = datetime.fromtimestamp(session_accessed).strftime("%Y-%m-%d %H:%M:%S")
            offline_session = {"start_time": session_start_time, "accessed_time": session_accessed_time}
        offline_token = session.get("offline_token")

    return render_template("home.html",
                           login_url=url_for(".login"),
                           logout_url=url_for(".logout"),
                           token_url=url_for(".get_token"),
                           invalidate_url=url_for(".invalidate_session"),
                           offline_session=offline_session,
                           offline_token=offline_token)


@app.route("/login")
def login():
    oauth = OAuth2Session(client_id, redirect_uri=login_callback_url)
    authorization_url, state = oauth.authorization_url(authorization_base_url)

    session["oauth_state"] = state
    target_url = f"{logout_url}?redirect_uri={quote(authorization_url)}"
    return redirect(target_url)


@app.route("/login-callback", methods=["GET"])
def login_callback():
    oauth = OAuth2Session(client_id, redirect_uri=login_callback_url, state=session["oauth_state"])
    oauth_token = oauth.fetch_token(token_url, authorization_response=request.url, verify=False)

    d = oauth_token.get("access_token").split(".")[1]
    decoded_token = base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))
    payload = json.loads(decoded_token)
    session["user_uid"] = payload["sub"]

    return redirect(url_for(".home"))


@app.route("/get_token")
def get_token():
    oauth = OAuth2Session(client_id, redirect_uri=token_callback_url, scope="offline_access")
    authorization_url, state = oauth.authorization_url(authorization_base_url)

    session["oauth_state"] = state
    return redirect(authorization_url)


@app.route("/token-callback", methods=["GET"])
def token_callback():
    oauth = OAuth2Session(client_id, redirect_uri=token_callback_url, state=session["oauth_state"])
    oauth_token = oauth.fetch_token(token_url, authorization_response=request.url, verify=False)

    offline_token = oauth_token.get("refresh_token")
    session["offline_token"] = offline_token

    return redirect(url_for(".home"))


@app.route("/invalidate_session")
def invalidate_session():
    invalidate_keycloak_session(config)
    return redirect(url_for(".home"))


def get_keycloak_offline_sessions(config):
    token = get_keycloak_token(config)
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer %s" % token["access_token"],
    }
    user_uid = session["user_uid"]
    url = config["hzb"]["admin_url"] + \
        f"/users/{user_uid}/offline-sessions/{client_uid}"
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    return r.json()


def invalidate_keycloak_session(config):
    token = get_keycloak_token(config)
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer %s" % token["access_token"],
    }
    user_uid = session["user_uid"]
    url = config["hzb"]["admin_url"] + \
        f"/users/{user_uid}/consents/{client_id}"
    r = requests.delete(url, headers=headers)
    r.raise_for_status()


def get_keycloak_token(config):
    data = {
        "grant_type": "client_credentials",
        "client_id": config["admin-cli"]["client_id"],
        "client_secret": config["admin-cli"]["client_secret"],
    }
    url = config["admin-cli"]["realm_url"] + \
        "/protocol/openid-connect/token"
    r = requests.post(url, data=data)
    r.raise_for_status()
    return r.json()


@app.route("/logout")
def logout():
    session.clear()
    target_url = f"{logout_url}?redirect_uri={quote(client_base_url)}"
    return redirect(target_url)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    app.secret_key = os.urandom(24)
    app.run(host="localhost", debug=True)
