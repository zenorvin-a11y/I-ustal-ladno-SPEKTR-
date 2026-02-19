import os
import sys
import datetime
import traceback
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from werkzeug.utils import secure_filename
from sqlalchemy import or_

print("="*60)
print("ЗАПУСК ПРИЛОЖЕНИЯ С ДИАГНОСТИКОЙ")
print("="*60)
print(f"Python версия: {sys.version}")
print(f"Текущая директория: {os.getcwd()}")
print(f"Содержимое директории: {os.listdir('.')}")

# Проверка переменных окружения
print("-"*30)
print("ПРОВЕРКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ:")
print(f"GOOGLE_CLIENT_ID найден: {'GOOGLE_CLIENT_ID' in os.environ}")
print(f"GOOGLE_CLIENT_SECRET найден: {'GOOGLE_CLIENT_SECRET' in os.environ}")
print("-"*30)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spektr-super-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spektr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/avatars'
app.config['GROUP_UPLOAD_FOLDER'] = 'static/group_avatars'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

print("Создание папок для аватарок...")
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['GROUP_UPLOAD_FOLDER'], exist_ok=True)
    print(f"✅ Папки созданы: {app.config['UPLOAD_FOLDER']}, {app.config['GROUP_UPLOAD_FOLDER']}")
except Exception as e:
    print(f"❌ Ошибка создания папок: {e}")

print("Инициализация базы данных...")
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'glavnaya'

# ========== МОДЕЛИ ==========
print("Создание моделей...")
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default='/static/logo.png')
    theme = db.Column(db.String(20), default='dark')
    notifications = db.Column(db.Boolean, default=True)
    sound = db.Column(db.Boolean, default=True)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', backref='sender', lazy=True)
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', backref='receiver', lazy=True)
    friends = db.relationship('Friend', foreign_keys='Friend.user_id', backref='user', lazy=True)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])
    friend = db.relationship('User', foreign_keys=[friend_id])

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    avatar = db.Column(db.String(200), default='/static/group.png')
    is_public = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', foreign_keys=[creator_id])
    members = db.relationship('GroupMember', backref='group', lazy=True)
    messages = db.relationship('GroupMessage', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    is_admin = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])

print("✅ Модели созданы")

# Создание таблиц
print("Создание таблиц базы данных...")
try:
    with app.app_context():
        db.create_all()
        print("✅ Таблицы созданы успешно")
        
        # Создаём админа если нет
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin = User(
                email='admin@spektr.ru',
                name='Admin',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Админ создан")
except Exception as e:
    print(f"❌ Ошибка при создании таблиц: {e}")
    traceback.print_exc()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== GOOGLE OAUTH ==========
client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")

if client_id and client_secret:
    try:
        google_bp = make_google_blueprint(
            client_id=client_id,
            client_secret=client_secret,
            scope=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
            redirect_to="glavnaya"
        )
        app.register_blueprint(google_bp, url_prefix="/login")
        print("✅ Google OAuth настроен")
    except Exception as e:
        print(f"❌ Ошибка настройки Google OAuth: {e}")
        traceback.print_exc()

    @oauth_authorized.connect_via(google_bp)
    def google_logged_in(blueprint, token):
        try:
            resp = blueprint.session.get("/oauth2/v2/userinfo")
            if resp.ok:
                user_info = resp.json()
                email = user_info.get('email')
                
                user = User.query.filter_by(email=email).first()
                if not user:
                    user = User(
                        email=email,
                        name=user_info.get('name'),
                        avatar=user_info.get('picture', '/static/logo.png')
                    )
                    db.session.add(user)
                    db.session.commit()
                    print(f"✅ Новый пользователь создан: {email}")
                
                if user.is_banned:
                    return "Ваш аккаунт заблокирован. Причина: " + user.ban_reason, 403
                
                login_user(user)
                session['user_id'] = user.id
                print(f"✅ Пользователь вошёл: {email}")
        except Exception as e:
            print(f"❌ Ошибка при входе через Google: {e}")
            traceback.print_exc()

# ========== МАРШРУТЫ ==========
@app.route('/')
def glavnaya():
    try:
        if current_user.is_authenticated and current_user.is_banned:
            logout_user()
            return render_template('glavnaya.html', user=None, banned=True)
        return render_template('glavnaya.html', user=current_user if current_user.is_authenticated else None)
    except Exception as e:
        print(f"❌ Ошибка на главной: {e}")
        traceback.print_exc()
        return "Ошибка сервера", 500

@app.route('/profile')
def profile():
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('glavnaya'))
        return render_template('profile.html', user=current_user)
    except Exception as e:
        print(f"❌ Ошибка в профиле: {e}")
        traceback.print_exc()
        return "Ошибка сервера", 500

@app.route('/messages')
def messages():
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('glavnaya'))
        
        friends = Friend.query.filter_by(user_id=current_user.id).all()
        friend_users = [f.friend for f in friends]
        
        incoming_requests = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
        outgoing_requests = FriendRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
        
        last_messages = []
        for friend in friend_users:
            last_msg = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == friend.id)) |
                ((Message.sender_id == friend.id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp.desc()).first()
            if last_msg:
                unread_count = Message.query.filter_by(
                    sender_id=friend.id, 
                    receiver_id=current_user.id, 
                    is_read=False
                ).count()
                
                last_messages.append({
                    'friend': friend,
                    'last_message': last_msg,
                    'unread': unread_count
                })
        
        return render_template('messages.html',
                              user=current_user,
                              friends=friend_users,
                              incoming_requests=incoming_requests,
                              outgoing_requests=outgoing_requests,
                              last_messages=last_messages)
    except Exception as e:
        print(f"❌ Ошибка в сообщениях: {e}")
        traceback.print_exc()
        return "Ошибка сервера", 500

@app.route('/obshchenie')
def obshchenie():
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('glavnaya'))
        
        groups = Group.query.all()
        
        return render_template('obshchenie.html', 
                              user=current_user, 
                              groups=groups)
    except Exception as e:
        print(f"❌ Ошибка в группах: {e}")
        traceback.print_exc()
        return "Ошибка сервера", 500

# ... остальные маршруты (я их сократил для краткости, но они должны быть)

print("="*60)
print("✅ ПРИЛОЖЕНИЕ ЗАПУЩЕНО")
print("="*60)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
