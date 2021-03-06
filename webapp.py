from __future__ import print_function
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, flash, Markup
from flask_oauthlib.client import OAuth

from github import Github

import os
import pprint
import sys
import traceback
import base64
import markdown

class GithubOAuthVarsNotDefined(Exception):
	'''raise this if the necessary environmental vars are not defined'''

# Check if environmental variables are set
if (os.getenv('GITHUB_CLIENT_ID') == None or\
os.getenv('GITHUB_CLIENT_SECRET') == None or\
os.getenv('APP_SECRET_KEY') == None or\
os.getenv('GITHUB_ORG') == None):
	raise GithubOAuthVarsNotDefined('''
		Please define environment variables:
			GITHUB_CLIENT_ID
			GITHUB_CLIENT_SECRET
			GITHUB_ORG
			APP_SECRET_KEY
		''')

# Create Flask app
app = Flask(__name__)

# Assign APP_SECRET_KEY for using Sessions
app.secret_key = os.getenv('APP_SECRET_KEY')

# Creat OAuth object for OAuth calls
oauth = OAuth(app)

# Connect to GitHub
github = oauth.remote_app(
    'github',
    consumer_key=os.getenv('GITHUB_CLIENT_ID'),
    consumer_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    request_token_params={'scope': 'read:org, repo'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)

@app.context_processor
def inject_logged_in():
    return dict(logged_in=logged_in())

@app.context_processor
def inject_github_org():
    return dict(github_org=os.getenv('GITHUB_ORG'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You were logged out')
    return redirect(url_for('home'))

@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()

	# No response from GitHub, deny login
    if resp is None:
        session.clear()
        login_error_message = 'Access denied: reason=%s error=%s full=%s' % (
            request.args['error'],
            request.args['error_description'],
            pprint.pformat(request.args)
        )
        flash(login_error_message, 'error')
        return redirect(url_for('home'))

	# Try getting access token from response
    try:
        session['github_token'] = (resp['access_token'], '')
        session['user_data']=github.get('user').data
        github_userid = session['user_data']['login']
        org_name = os.getenv('GITHUB_ORG')

	# Throw exception if access token is not given or there is trouble with using the token
    except Exception as e:
        session.clear()
        message = 'Unable to login: ' + str(type(e)) + str(e)
        flash(message,'error')
        return redirect(url_for('home'))

	# Try using token to get user information
    try:
        g = Github(resp['access_token'])
        org = g.get_organization(org_name)
        named_user = g.get_user(github_userid)
        isMember = org.has_in_members(named_user)

	# Throw exception if token cannot get information
    except Exception as e:
        message = 'Unable to connect to Github with accessToken: ' + resp['access_token'] + " exception info: " + str(type(e)) + str(e)
        session.clear()
        flash(message,'error')
        return redirect(url_for('home'))

	# Check if user is member of given GITHUB_ORG
    if not isMember:
        session.clear() # Must clear session before adding flash message
        message = 'Unable to login: ' + github_userid + ' is not a member of ' + org_name + \
          '</p><p><a href="https://github.com/logout" target="_blank">Logout of github as user:  ' + github_userid + \
          '</a></p>'
        flash(Markup(message),'error')

    else:
        flash('You were successfully logged in')

    return redirect(url_for('home'))


@app.route('/feedback')
def renderFeedback():
    if not logged_in():
        flash('You must be logged in to do that', 'error')
        return redirect(url_for('home'))
    user_feedback = []
    g = Github(get_github_oauth_token()[0])
    repos = g.get_organization(os.getenv('GITHUB_ORG')).get_repos()
    named_user = g.get_user(session['user_data']['login'])
    for repo in repos:
        if (repo.name[0:8].upper() == 'FEEDBACK'):
            if (repo.has_in_collaborators(named_user)):
                user_feedback.append(Markup(markdown.markdown(bytes.decode(base64.b64decode(repo.get_contents('README.md').content)))))
    return render_template('feedback.html',list_feedback=user_feedback)


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

# Checks if token is in session, which means that the user is logged in
def logged_in():
    return 'github_token' in session

if __name__ == '__main__':
    app.run()
