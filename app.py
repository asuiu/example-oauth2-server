# coding: utf-8
import json
import logging
import random
import time
from datetime import datetime, timedelta

from flask import Flask, Response
from flask import render_template, redirect, jsonify
from flask import session, request
from flask_oauthlib.provider import OAuth2Provider
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)
oauth = OAuth2Provider(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)


class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id='bob',  # gen_salt(40),
        client_secret="WaPwJhgJD2pEsNZ50VHfhRwe0p8tdlsM6YkgwAa1P60QnzOyPo",  # gen_salt(50),
        _redirect_uris=' '.join([
            'http://localhost:8000/authorized',
            'http://127.0.0.1:8000/authorized',
            'http://127.0.1:8000/authorized',
            'http://127.1:8000/authorized',
            'https://zapier.com/dashboard/auth/oauth/return/App43044API/',
            'https://zapier.com/dashboard/auth/oauth/return/App43232API/',
            'https://zapier.com/dashboard/auth/oauth/return/App43424API/'
        ]),
        _default_scopes='email',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
# @oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)


class AutoIncrementedId:
    def __init__(self):
        self.__i = 0

    def __call__(self, *args, **kwargs):
        self.__i += 1
        return self.__i


globalCounter = AutoIncrementedId()


@app.route('/trigger1')
# @oauth.require_oauth()
def trigger1():
    # user = request.oauth.user
    # json_data = [dict(data=user.username + str(random.randint(0, 10000)),
    #                    trigger_field_key="field_key" + str(random.randint(0, 1000)))]
    user = "not_authenticated"
    json_data = [dict(id=random.randint(0, 1000), data=user + str(globalCounter()))]

    # data = json.dumps(json_data)
    # resp = Response(response=data, status=200, mimetype="application/json")
    print "Trigger1 sends: ", json_data
    return jsonify(results=json_data)


@app.route('/trigger2')
# @oauth.require_oauth()
def trigger2():
    json_data = [dict(id=random.randint(0, 1000), data2="data2_" + str(globalCounter()),
                      json2={"jsondata": "jsondata2_" + str(globalCounter())})]
    print "Trigger2 sends: ", json_data
    return jsonify(results=json_data)


@app.route('/profiles')
# @oauth.require_oauth()
def profiles():
    # user = request.oauth.user
    # json_data = [dict(data=user.username + str(random.randint(0, 10000)),
    #                    trigger_field_key="field_key" + str(random.randint(0, 1000)))]
    user = "not_authenticated"
    profile_list = [{"id": 1, "name": "profile1"}, {"id": 2, "name": "profile2"}]

    # data = json.dumps(json_data)
    # resp = Response(response=data, status=200, mimetype="application/json")
    print "Trigger1 sends: ", profile_list
    return jsonify(results=profile_list)


@app.route('/field1')
# @oauth.require_oauth()
def field1():
    json_data = [dict(id=random.randint(0, 1000), fielddata="fielddata_" + str(globalCounter()))]
    print "Field1 sends: ", json_data
    return jsonify(results=json_data)


@app.route('/action1', methods=['POST'])
# @oauth.require_oauth()
def action1():
    # user = request.oauth.user
    # return jsonify(data=user.username + str(random.randint(0, 10000)))
    print "Action1 got: ", request.json
    return jsonify(data=str(random.randint(0, 10000)))


PROCESS_IDS = {1234: {}}


@app.route('/profiles/<int:id>/eventNotifications', methods=['PATCH'])
# @oauth.require_oauth()
def patch_eventNotifications(id):
    processId = request.args.get('processId')
    PROCESS_IDS[id][processId] = time.time()
    data = json.dumps({})
    resp = Response(response=data, status=200, mimetype="application/json")
    resp.headers['Location'] = '/profiles/<int:id>/eventNotifications?processId=%s&page=1' % processId
    return resp


@app.route('/profiles/<int:id>/eventNotifications', methods=['GET'])
# @oauth.require_oauth()
def get_eventNotifications(id):
    processId = request.args.get('processId')
    page = int(request.args.get('page'))
    # if processId not in PROCESS_IDS[id]:
    #     resp = Response(response="processId for ID: %d doesn't exist"%id, status=404)
    #     return resp
    data = json.dumps([{"id": random.randint(0, 1000), "data": random.randint(0, 1000)},
                       {"id": random.randint(0, 1000), "data": random.randint(0, 1000)},
                       {"id": page, "data": random.randint(0, 1000)}])
    print "Sending %s to Action: " % data
    resp = Response(response=data, status=200, mimetype="application/json")
    resp.headers['Location'] = '/profiles/<int:id>/eventNotifications?processId=%s&page=1&page' % processId
    return resp


@app.route('/profiles/<int:id>/eventNotifications', methods=['DELETE'])
# @oauth.require_oauth()
def delete_eventNotifications(id):
    processId = request.args.get('processId')
    if processId not in PROCESS_IDS[id]:
        resp = Response(response="processId doesn't exist", status=404)
        return resp
    del PROCESS_IDS[id][processId]
    data = json.dumps({"deleted": processId})
    resp = Response(response=data, status=200, mimetype="application/json")
    resp.headers['Location'] = '/profiles/<int:id>/eventNotifications?processId=%s&page=1&page' % processId
    return resp


@app.route('/me')
# @oauth.require_oauth()
def pure360_me():
    data = '''{"id":"12917","login":"jakubsikoratest","impersonating":false,"group":{"id":"11622","self":"/groups/11622"},"email":"jakub.sikora@pure360.com","name":"Jakub Sikora","phone":"01234567890","lastLogin":"2016-09-20T09:40:08Z","lastItemAccess":"2014-04-24T16:19:00Z","lastRole":{"roleType":"profile","profile":{"id":"13759"}},"licenceAcceptance":true,"blankTemplateAcceptedDate":null,"active":true,"profiles":[{"id":"13759","self":"/profiles/13759","title":"jakub.sikora"},{"id":"14016","self":"/profiles/14016","title":"cosworth"}],"views":[{"type":"profile","id":"13759","permissions":["allowLimitReceipt","POST:/feedback","POST:/help","GET:/components/$","GET:/emails/$","GET:/emails/$/bodies","GET:/emails/$/bodies/$","GET:/emails/$/bodies/$/$","GET:/profiles/$/components","GET:/profiles/$/customFields","GET:/profiles/$/emails","GET:/profiles/$/messages","GET:/profiles/$/templates","POST:/emails/$/test","POST:/components","POST:/emails","POST:/emails/$/bodies","POST:/emails/$/spamCheck","PUT:/components/$","PUT:/emails/$","PUT:/emails/$/bodies/$","PUT:/emails/$/bodies/$/$","PATCH:/components/$","PATCH:/emails/$","PATCH:/emails/$/bodies/$","DELETE:/components/$","DELETE:/emails/$","DELETE:/emails/$/bodies/$","DELETE:/snippets/$","GET:/profiles/$/snippets","GET:/snippets/$","GET:/systemSnippets","GET:/systemSnippets/$","POST:/snippets","PUT:/snippets/$","GET:/profiles/$/contacts","GET:/contacts/export","GET:/contacts/$","GET:/profiles/$/lists","GET:/profiles/$/listsUserNames","GET:/lists/$","GET:/lists/$/export","GET:/lists/$/filters/$","GET:/lists/$/filters/$/export","GET:/profiles/$/searches","GET:/searches/$","GET:/lists/$/fields","GET:/lists/$/contacts","POST:/contacts","POST:/lists","POST:/lists/$/data","POST:/lists/$/filters","POST:/profiles/$/listUploads","GET:/profiles/$/listUploads/$","PATCH:/contacts/$","PATCH:/lists/$","PUT:/lists/$/filters/$","PATCH:/lists/$/clean","PATCH:/lists/$/data","DELETE:/lists/$","DELETE:/lists/$/filters/$","DELETE:/lists/$/contacts/$","createListFromReport","GET:/profiles/$/campaigns","GET:/campaigns/$","GET:/campaigns/$/resends/$","POST:/campaigns","GET:/profiles/$/credits","POST:/campaigns/$/resends","PUT:/campaigns/$","PATCH:/campaigns/$","PATCH:/campaigns/$/resends/$","PUT:/campaigns/$/resends/$","GET:/geolocation/countries","GET:/geolocation/locations","GET:/profiles/$/reports","GET:/reports/$","GET:/reports/$/contacts","GET:/reports/$/exportSummary","GET:/reports/$/resends/$","GET:/reports/$/sentEmails/$","GET:/reports/$/sentEmails/$/bodies/$/$","GET:/reports/$/trackingBreakdown","GET:/reports/$/trackingBreakdownByDomain","GET:/reports/campaigns/$","GET:/reports/campaigns/$/analytics/profiles","GET:/reports/campaigns/$/analytics/profiles/$/metrics","GET:/reports/campaigns/$/clicks","GET:/reports/campaigns/$/clicks/distribution","GET:/reports/campaigns/$/clicks/email","GET:/reports/campaigns/$/clicks/performance","GET:/reports/campaigns/$/demographics","GET:/reports/campaigns/$/highlights","GET:/reports/campaigns/$/linkSummary","GET:/reports/campaigns/$/opens","GET:/reports/campaigns/$/opens/subjectLine","GET:/reports/campaigns/$/opensAndClicksByDomain","GET:/reports/campaigns/$/opensByCountry","GET:/reports/campaigns/$/opensByLocation","GET:/reports/campaigns/$/opensClicksPerformance","GET:/reports/campaigns/$/sentDelivered","GET:/reports/campaigns/$/sentDelivered/domain","GET:/reports/campaigns/$/social/bitly","GET:/reports/campaigns/$/social/facebook","GET:/reports/campaigns/$/social/repliesAndForwards","GET:/reports/campaigns/$/social/twitter","GET:/reports/campaigns/$/subscriberActivity/clicks","GET:/reports/campaigns/$/subscriberActivity/opens","GET:/reports/campaigns/$/subscriberActivity/sentDelivered","GET:/reports/$/export","GET:/reports/timeline","POST:/searches","PATCH:/searches/$","PUT:/searches/$","DELETE:/searches/$","PATCH:/profiles/$","GET:/profiles/$/uploads","GET:/profiles/$/uploads/$","DELETE:/profiles/$/uploads/$","POST:/profiles/$/uploads/$","POST:/profiles/$/uploads","POST:/emails/$/litmus","GET:/emails/$/litmus","GET:/emails/$/litmus/$","GET:/litmus/status","allowDynamicReply","allowITS","GET:/profiles/$/automations","GET:/dateAutomations/$","GET:/reports/dateAutomations","GET:/reports/dateAutomations/$","GET:/reports/dateAutomations/$/timeline","GET:/signupAutomations/$","GET:/reports/signupAutomations","GET:/reports/signupAutomations/$","GET:/reports/signupAutomations/$/timeline","POST:/dateAutomations","POST:/signupAutomations","PUT:/signupAutomations/$","PUT:/dateAutomations/$","PATCH:/signupAutomations/$","PATCH:/dateAutomations/$","DELETE:/signupAutomations/$","DELETE:/dateAutomations/$","showPurePromotions","showPureTargeting","connectTm","GET:/profiles/$/authorizationCode","editPureTargetingApiKey"]},{"type":"group","id":"11622","permissions":[]}]}'''

    resp = Response(response=data, status=200, mimetype="application/json")
    return resp



from flask_oauthlib.provider.oauth2 import log as oauth_log

if __name__ == '__main__':
    db.create_all()
    # oauth_log = logging.getLogger('flask_oauthlib')
    oauth_log.setLevel(logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)
    app.run(port=80, debug=True, host='0.0.0.0')
    # app.run(port=443, debug=True, ssl_context='adhoc')
