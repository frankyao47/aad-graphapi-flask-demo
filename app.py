#!/usr/bin/env python
# coding: utf-8

from flask import Flask, render_template, request, abort, jsonify, redirect, session, url_for
import requests, json
from functools import wraps

oauth_authorization_url = 'https://login.chinacloudapi.cn/22d9d915-574d-43c7-b985-72aa3a7b979e/oauth2/authorize'
oauth_token_url = 'https://login.chinacloudapi.cn/22d9d915-574d-43c7-b985-72aa3a7b979e/oauth2/token'
graph_api_url = 'https://graph.chinacloudapi.cn/22d9d915-574d-43c7-b985-72aa3a7b979e'
client_id = '1a20bd8c-26f7-47de-a4eb-b5570ad94412' #client id
client_secret = 'MkNxGLVsU2G4Ql3IscDJJkBwxvz+5o74HEh8+vMGfb0=' #key
reply_url = 'http://localhost:5000/auth' #reply url
domain_name = 'yaofangjie.partner.mail.onmschina.cn' #register user domain

app = Flask(__name__)
app.secret_key = '123456'

#oauth authorization
def get_aad_login_url():
    params = {
        'url': oauth_authorization_url,
        'response_type': 'code',
        'client_id': client_id, #client_id
        'redirect_uri': reply_url, #reply url
    }

    redirect_url = '%(url)s?response_type=%(response_type)s&client_id=%(client_id)s&redirect_uri=%(redirect_uri)s' %params
    return redirect_url


#oauth get access
def get_access_token_by_code(code):
    payload = {
        'client_id': client_id,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': reply_url,
        'resource': 'https://graph.chinacloudapi.cn',
        'client_secret': client_secret
    }
    r = requests.post(oauth_token_url, data=payload)
    return r.json().get('access_token', '')


#access token is required in session
def access_token_required(func):
    @wraps(func)
    def __decorator():
        if not session.get('access_token'):
            return redirect(url_for('index'))
        return func()

    return __decorator


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET'])
def login():
    redirect_url = get_aad_login_url()
    return redirect(redirect_url, code=301)


@app.route('/auth', methods=['GET'])
def auth():
    code = request.args.get('code', '')
    session['access_token'] = get_access_token_by_code(code)
    return redirect(url_for('list_user'))


@app.route('/user/list', methods=['GET'])
@access_token_required
def list_user():
    users = _list_user(session['access_token'])
    return render_template('list_user.html', users=users)


@app.route('/user/me', methods=['GET'])
@access_token_required
def get_user():
    user = _get_user(session['access_token'])
    return render_template('user.html', user=user)


@app.route('/user/add', methods=['GET', 'POST'])
@access_token_required
def add_user():
    if request.method == 'POST':
        return _add_user(session['access_token'], request.form)
    else:
        return render_template('add_user.html')

@app.route('/error', methods=['GET'])
def display_error():
    messages = json.loads(request.args['messages'])
    error_code = messages.get('error_code')
    error_message = messages.get('error_message')
    return render_template('error.html', error_code=error_code, error_message=error_message)


def _handle_errors(r):
    errors = r.json().get('odata.error')
    if errors:
        error_code = errors.get('code')
        error_message = errors.get('message').get('value')
        messages = json.dumps({'error_code': error_code, 'error_message': error_message})
        return redirect(url_for('display_error', messages=messages))
    else:
        return redirect(url_for('list_user'))

def _get_headers(access_token):
    return {
        'Authorization': 'Bearer ' + access_token,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

def _get_user(access_token):
    url = graph_api_url + '/me' + '?api-version=1.6'
    headers = _get_headers(access_token)

    r = requests.get(url, headers=headers)
    return r.json()


def _list_user(access_token):
    url = graph_api_url + '/users' + '?api-version=1.6'
    headers = _get_headers(access_token)

    r = requests.get(url, headers=headers)
    return r.json()['value']


def _add_user(access_token, form):
    url = graph_api_url + '/users' + '?api-version=1.6'
    headers = _get_headers(access_token)
    body = {
        "accountEnabled": "true",
        "displayName": form.get('displayName', 'Test'),
        "mailNickname": form.get('userPrincipalName', 'Test'),
        "passwordProfile": {
            "password": form.get('password', 'Tes,234'),
            "forceChangePasswordNextLogin": "false"
        },
        "userPrincipalName": form.get('userPrincipalName', 'Test') + "@" + domain_name
    }

    r = requests.post(url, headers=headers, data=json.dumps(body))
    return _handle_errors(r)
    


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)