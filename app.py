#!/usr/bin/env python
# coding: utf-8

from flask import Flask, render_template, request, redirect, session, url_for
import requests, json, jwt
from functools import wraps


oauth_authorization_url = 'https://login.chinacloudapi.cn/common/oauth2/authorize'
oauth_token_url = 'https://login.chinacloudapi.cn/common/oauth2/token'
graph_api_url = 'https://graph.chinacloudapi.cn'

client_id = '1a20bd8c-26f7-47de-a4eb-b5570ad94412' #client id
client_secret = 'MkNxGLVsU2G4Ql3IscDJJkBwxvz+5o74HEh8+vMGfb0=' #key
reply_url = 'http://localhost:5000/auth' #reply url

app = Flask(__name__)
app.secret_key = 'Your should replace it.'

#######################################functions#########################################
#reference: https://msdn.microsoft.com/zh-CN/library/azure/dn645542.aspx

#oauth authorization, request code
def get_oauth_authorization_url(prompt_admin_consent=False):
    params = {
        'url': oauth_authorization_url,
        'response_type': 'code',
        'client_id': client_id, #client_id
        'redirect_uri': reply_url, #reply url
        'resource': graph_api_url,
        'prompt': 'login' #personal consent, only affect current user
    }
    if prompt_admin_consent:
        params['prompt'] = 'admin_consent' #tenant consent, affect all users in the tenant

    redirect_url = '%(url)s?response_type=%(response_type)s&client_id=%(client_id)s&resource=%(resource)s\
&redirect_uri=%(redirect_uri)s&prompt=%(prompt)s' %params
    return redirect_url


#oauth get access token
def set_oauth_access_token_by_code(code):
    payload = {
        'client_id': client_id,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': reply_url,
        'resource': graph_api_url,
        'client_secret': client_secret
    }
    oauth_response = requests.post(oauth_token_url, data=payload)
    oauth_response_json = oauth_response.json()

    session['access_token'] = oauth_response_json.get('access_token') #access_token: app use it to request Web API
    session['id_token'] = jwt.decode(oauth_response_json.get('id_token'), verify=False) #id_token: login user's info
    session['refresh_token'] = oauth_response_json.get('refresh_token') #refresh_token: app use it to refresh access token
    
    session['tenant_id'] = session['id_token'].get('tid', '')
    
    return 


#access token is required in session
def access_token_required(func):
    @wraps(func)
    def __decorator():
        if not session.get('access_token'):
            return redirect(url_for('index'))
        return func()

    return __decorator


#Http header for web API requests
def _get_headers(access_token):
    return {
        'Authorization': 'Bearer ' + access_token,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }


#graph api
#reference: https://msdn.microsoft.com/zh-cn/library/azure/ad/graph/api/api-catalog
def _list_user(access_token, tenant_id):
    url = graph_api_url + '/%s/users?api-version=1.6' %(tenant_id)
    headers = _get_headers(access_token)

    response = requests.get(url, headers=headers)
    return response.json().get('value')


def _get_user(access_token):
    url = graph_api_url + '/me?api-version=1.6'
    headers = _get_headers(access_token)

    response = requests.get(url, headers=headers)
    return response.json()



#######################################route#########################################
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.route('/signin', methods=['GET'])
def signin():
    redirect_url = get_oauth_authorization_url(prompt_admin_consent=False)
    return redirect(redirect_url, code=301)


@app.route('/signin_admin', methods=['GET'])
def signin_admin():
    redirect_url = get_oauth_authorization_url(prompt_admin_consent=True)
    return redirect(redirect_url, code=301)


@app.route('/auth', methods=['GET'])
def auth():
    code = request.args.get('code', '')
    set_oauth_access_token_by_code(code)
    return redirect(url_for('get_user'))


@app.route('/user/me', methods=['GET'])
@access_token_required
def get_user():
    user = _get_user(session['access_token'])
    return render_template('user.html', user=user)


@app.route('/user/list', methods=['GET'])
@access_token_required
def list_users():
    users = _list_user(session['access_token'], session['tenant_id'])
    return render_template('list_user.html', users=users)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)