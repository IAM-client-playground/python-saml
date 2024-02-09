from flask import Flask, request, redirect, url_for, render_template_string
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

app = Flask(__name__)


def init_saml_auth(req):
    # Define the path to the SAML settings and certificates
    saml_settings_path = os.path.join(os.getcwd())
    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_settings_path)
    return auth


def prepare_flask_request(request):
    # Adapt Flask request object for python-saml
    url_data = request.url.split('?')
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ['SERVER_PORT'],
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


@app.route('/')
def index():
    return "Flask SAML SP Example"


@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())


@app.route('/saml/logout')
def saml_logout():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.logout())


@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        return redirect(url_for('index'))
    else:
        return render_template_string("Error: {{errors}}", errors=errors)


@app.route('/saml/metadata/')
def saml_metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = app.make_response(metadata)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
    else:
        return render_template_string("Error found in metadata: {{errors}}", errors=', '.join(errors))


if __name__ == '__main__':
    app.run(debug=True)
