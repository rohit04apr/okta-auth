from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout
#import subprocess as sub
import os
import random
import string

from .models import DiscoveryDocument, Config, TokenManager
from .decorators import okta_login_required

import json
import requests
from .tokens import TokenValidator
from .oauth_openid import call_userinfo_endpoint, call_introspect, call_revocation

# GLOBALS
config = Config()
token_manager = TokenManager()
random_string=(''.join(random.choice(string.ascii_lowercase) for i in range(10)))



def get_context(request):
    context = {'active': True}

    if 'tokens' in request.session:
        context['tokens'] = request.session['tokens']
        if 'claims' in request.session['tokens']:
            context['claims'] = json.dumps(request.session['tokens']['claims'],
                                           sort_keys=True, indent=4)

    if 'userInfo' in request.session:
        context['userInfo'] = request.session['userInfo']

    if 'introspect' in request.session:
        context['introspect'] = request.session['introspect']

    if 'revocation' in request.session:
        context['revocation'] = request.session['revocation']

    return context


def login_controller(request):
    if config.okta_admin_enabled == "True":
        okta_config = {
            'clientId': config.client_id,
            'url': config.org_url,
            'redirectUri': str(config.redirect_uri),
            'scope': config.scopes,
            'issuer': config.issuer
        }
        response = render(request, 'login.html', {'config': okta_config})

        _delete_cookies(response)

        return response
    else:
        url = ""+config.org_url+"/oauth2/default/v1/authorize?client_id="+config.client_id+"&redirect_uri="+str(config.redirect_uri)+"&response_type=code&response_mode=query&state="+random_string+"&nonce="+random_string+"&scope=openid%20profile%20email"
        return HttpResponseRedirect(url)


def callback_controller(request):
    def _token_request(auth_code, nonce):
        # authorization_code flow. Exchange the auth_code for id_token and/or access_token
        user = None

        validator = TokenValidator(config)
        tokens = validator.call_token_endpoint(auth_code)

        if tokens is not None:
            if 'id_token' in tokens:
                # Perform token validation
                claims = validator.validate_token(tokens['id_token'], nonce)

                if claims:
                    token_manager.set_id_token(tokens['id_token'])
                    token_manager.set_claims(claims)
                    user = _validate_user(claims)

            if 'access_token' in tokens:
                token_manager.set_access_token(tokens['access_token'])


        return user, token_manager.getJson()

    if request.POST:
        return HttpResponse({'error': 'Endpoint not supported'})
    else:
        code = request.GET['code']
        state = request.GET['state']

        # Get state and nonce from cookie
        if config.okta_admin_enabled == "True":
            cookie_state = request.COOKIES["okta-oauth-state"]
            cookie_nonce = request.COOKIES["okta-oauth-nonce"]
        else:
            cookie_nonce = random_string

        if config.okta_admin_enabled == "True":
        # Verify state
            if state != cookie_state:
                raise Exception("Value {} does not match the assigned state".format(state))
                return HttpResponseRedirect(reverse('login_controller'))

        user, token_manager_json = _token_request(code, cookie_nonce)
        if user is None:
            return redirect('/login')
        else:
            login(request, user)

        request.session['tokens'] = token_manager_json
        return redirect('/')


@login_required(redirect_field_name=None, login_url='/login')
@okta_login_required
def home_controller(request):

    context = get_context(request)
    email = context['tokens']['claims']['email']
    gitname = str.lower(email.split('@')[0].replace("_", "-"))

    token = os.environ.get('GITHUB_TOKEN')
    headers = {'Authorization': 'token ' + token}

    status_check = requests.get('https://{git_url}/api/v3/' + 'users/' + gitname, headers=headers)
    load_status = json.loads(status_check.content)
    if load_status['suspended_at'] == None:
        user_active = "User %s is already active on GHE." % gitname

        response = render(request, 'home.html', {'user_active': user_active, 'context': context})
    else:
        response = render(request, 'home.html', get_context(request))

    _delete_cookies(response)
    return response



def _get_user_by_username(username):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return None
    return user


def _validate_user(claims):
    # Create user for django session
    user = _get_user_by_username(claims['email'])
    if user is None:
        # Create user
        user = User.objects.create_user(
            username=claims['email'],
            email=claims['email']
        )
        print("User JIT")
    else:
        print("User exists")

    return user


def _delete_cookies(response):
    response.set_cookie('okta-oauth-state', '', max_age=3600)
    response.set_cookie('okta-oauth-nonce', '', max_age=3600)
    response.set_cookie('okta-oauth-redirect-params', '', max_age=3600)
    response.set_cookie('sessionid', '', max_age=3600)

def unlock(request):
    context = get_context(request)
    email = request.POST.get('email')
    if email:
        try:
            gitname = str.lower(email.split('@')[0].replace("_", "-"))
            token = os.environ.get('GITHUB_TOKEN')
            headers = {'Authorization': 'token ' + token}

            login = requests.delete('https://{git_url}/api/v3/' + 'users/' + gitname + '/suspended', headers=headers)

            if login.status_code == 204:
                output = "User %s has been unsuspended." % gitname
                errors = ''
            else:
                errors = "An error occurred while unsuspending.. Please check with  Admins"
                output = ''

            print('----Start Logger---')
            print("unsuspend api called with response :: %s " % output)
            print('----End Logger---')

        except Exception as er:
                print("FAILING due to :: %s " % er)


        return render(request, 'home.html', {'output': output, 'errors': errors, 'context': context})
    else:
        return render(request, 'home.html', {'errors': "User Not Allowed to run unsuspend command multiple times. Please refresh or re-login again", 'context': context})
