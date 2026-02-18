import os
from flask import Flask, render_template, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized

app = Flask(__name__)
app.secret_key = "spectrum-simple-key-2026"

# Google OAuth
client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")

if client_id and client_secret:
    google_bp = make_google_blueprint(
        client_id=client_id,
        client_secret=client_secret,
        scope=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
        redirect_to="glavnaya"
    )
    app.register_blueprint(google_bp, url_prefix="/login")
    print("✅ Google вход настроен")
else:
    print("⚠️ Google ключи не найдены")

@app.route('/')
def glavnaya():
    user = session.get('user')
    return render_template('glavnaya.html', user=user)

@app.route('/login/google')
def google_login():
    return redirect(url_for("google.login"))

@app.route('/vyhod')
def vyhod():
    session.clear()
    return redirect(url_for('glavnaya'))

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if resp.ok:
        session['user'] = resp.json()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
