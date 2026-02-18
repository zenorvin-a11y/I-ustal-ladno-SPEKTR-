import os
from flask import Flask, render_template, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized

app = Flask(__name__)
app.secret_key = "spektr-secret-key-2026"

# Настройка Google OAuth
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
    print("✅ Google вход настроен для spektr-ogzo.onrender.com")
    print(f"   Redirect URI: https://spektr-ogzo.onrender.com/login/google/authorized")
else:
    print("⚠️ Google ключи не найдены")

# Главная страница
@app.route('/')
def glavnaya():
    user = session.get('user')
    return render_template('glavnaya.html', user=user)

# Страница профиля (только для авторизованных)
@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        return redirect(url_for('glavnaya'))
    return render_template('profile.html', user=user)

# Страница групп (только для авторизованных)
@app.route('/groups')
def groups():
    user = session.get('user')
    if not user:
        return redirect(url_for('glavnaya'))
    return render_template('groups.html', user=user)

# Страница условий (доступна всем)
@app.route('/terms')
def terms():
    return render_template('terms.html')

# Вход через Google
@app.route('/login/google')
def google_login():
    return redirect(url_for("google.login"))

# Выход
@app.route('/vyhod')
def vyhod():
    session.clear()
    return redirect(url_for('glavnaya'))

# Обработчик успешного входа
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_info = resp.json()
        session['user'] = user_info
        print(f"✅ Пользователь {user_info.get('email')} вошёл")
    else:
        print("❌ Ошибка получения данных пользователя")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
