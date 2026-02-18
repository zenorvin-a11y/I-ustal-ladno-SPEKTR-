import os
import datetime
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spektr-super-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spektr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/avatars'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Создаём папку для аватарок если нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'glavnaya'

# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default='/static/logo.png')
    theme = db.Column(db.String(20), default='dark')
    notifications = db.Column(db.Boolean, default=True)
    sound = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    avatar = db.Column(db.String(200), default='/static/group.png')
    
    creator = db.relationship('User', foreign_keys=[creator_id])
    members = db.relationship('GroupMember', backref='group', lazy=True)
    messages = db.relationship('GroupMessage', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    is_admin = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

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

# Создаём таблицы
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== GOOGLE OAUTH ==========
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

    @oauth_authorized.connect_via(google_bp)
    def google_logged_in(blueprint, token):
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
            
            login_user(user)
            session['user_id'] = user.id

# ========== МАРШРУТЫ ==========
@app.route('/')
def glavnaya():
    return render_template('glavnaya.html', user=current_user if current_user.is_authenticated else None)

@app.route('/profile')
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    return render_template('profile.html', user=current_user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    # Обновляем настройки
    if 'theme' in request.form:
        current_user.theme = request.form.get('theme', 'dark')
    if 'notifications' in request.form:
        current_user.notifications = request.form.get('notifications') == 'on'
    if 'sound' in request.form:
        current_user.sound = request.form.get('sound') == 'on'
    
    # Загрузка аватарки
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            # Проверяем расширение
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext in app.config['ALLOWED_EXTENSIONS']:
                filename = secure_filename(f"user_{current_user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar = f'/static/avatars/{filename}'
    
    db.session.commit()
    
    # Если это AJAX запрос
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'avatar': current_user.avatar})
    
    return redirect(url_for('profile'))

@app.route('/obshchenie')
def obshchenie():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    # Получаем все группы
    groups = Group.query.all()
    
    # Получаем личные чаты
    sent_users = db.session.query(User).join(Message, Message.receiver_id == User.id).filter(Message.sender_id == current_user.id).distinct()
    received_users = db.session.query(User).join(Message, Message.sender_id == User.id).filter(Message.receiver_id == current_user.id).distinct()
    chat_users = sent_users.union(received_users).all()
    
    return render_template('obshchenie.html', user=current_user, groups=groups, chat_users=chat_users)

@app.route('/chat/<int:user_id>')
def private_chat(user_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    other_user = User.query.get_or_404(user_id)
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    # Отмечаем сообщения как прочитанные
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return render_template('private_chat.html', user=current_user, other_user=other_user, messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    if receiver_id and content:
        msg = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=content
        )
        db.session.add(msg)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid data'}), 400

@app.route('/group/<int:group_id>')
def group_chat(group_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    group = Group.query.get_or_404(group_id)
    
    # Проверяем, состоит ли пользователь в группе
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        membership = GroupMember(user_id=current_user.id, group_id=group_id)
        db.session.add(membership)
        db.session.commit()
    
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp).all()
    members = GroupMember.query.filter_by(group_id=group_id).all()
    
    return render_template('group_chat.html', user=current_user, group=group, messages=messages, members=members)

@app.route('/send_group_message', methods=['POST'])
def send_group_message():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    group_id = data.get('group_id')
    content = data.get('content')
    
    if group_id and content:
        msg = GroupMessage(
            user_id=current_user.id,
            group_id=group_id,
            content=content
        )
        db.session.add(msg)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid data'}), 400

@app.route('/create_group', methods=['POST'])
def create_group():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    name = request.form.get('name')
    description = request.form.get('description', '')
    
    if name:
        group = Group(
            name=name,
            description=description,
            creator_id=current_user.id
        )
        db.session.add(group)
        db.session.commit()
        
        # Добавляем создателя как админа
        membership = GroupMember(
            user_id=current_user.id,
            group_id=group.id,
            is_admin=True
        )
        db.session.add(membership)
        db.session.commit()
        
        return redirect(url_for('obshchenie'))
    
    return redirect(url_for('obshchenie'))

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/login/google')
def google_login():
    return redirect(url_for("google.login"))

@app.route('/vyhod')
def vyhod():
    logout_user()
    session.clear()
    return redirect(url_for('glavnaya'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
