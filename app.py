import os
import datetime
import hashlib
from flask import Flask, render_template, redirect, url_for, session, request, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spektr-super-secret-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spektr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/avatars'
app.config['GROUP_UPLOAD_FOLDER'] = 'static/group_avatars'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['GROUP_UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'glavnaya'
socketio = SocketIO(app, cors_allowed_origins="*")

# ========== МОДЕЛИ ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    password_hash = db.Column(db.String(200), nullable=True)
    avatar = db.Column(db.String(200), default='/static/logo.png')
    theme = db.Column(db.String(20), default='light')
    notifications = db.Column(db.Boolean, default=True)
    sound = db.Column(db.Boolean, default=True)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    registration_ip = db.Column(db.String(45), nullable=True)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver')
    group_memberships = db.relationship('GroupMember', back_populates='user')
    channel_memberships = db.relationship('ChannelMember', back_populates='user')
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', back_populates='sender')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', back_populates='receiver')
    friends_list = db.relationship('Friend', foreign_keys='Friend.user_id', back_populates='user')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class RegistrationAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_requests')

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], back_populates='friends_list')
    friend = db.relationship('User', foreign_keys=[friend_id])

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    avatar = db.Column(db.String(200), default='/static/group.png')
    is_public = db.Column(db.Boolean, default=True)
    is_private = db.Column(db.Boolean, default=False)
    
    creator = db.relationship('User', foreign_keys=[creator_id])
    members = db.relationship('GroupMember', back_populates='group')
    messages = db.relationship('GroupMessage', back_populates='group')

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    is_admin = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], back_populates='group_memberships')
    group = db.relationship('Group', foreign_keys=[group_id], back_populates='members')

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_public = db.Column(db.Boolean, default=True)
    
    creator = db.relationship('User', foreign_keys=[creator_id])
    members = db.relationship('ChannelMember', back_populates='channel')
    messages = db.relationship('ChannelMessage', back_populates='channel')

class ChannelMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], back_populates='channel_memberships')
    channel = db.relationship('Channel', foreign_keys=[channel_id], back_populates='members')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], back_populates='received_messages')

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])
    group = db.relationship('Group', foreign_keys=[group_id], back_populates='messages')

class ChannelMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])
    channel = db.relationship('Channel', foreign_keys=[channel_id], back_populates='messages')

with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            email='admin@spektr.ru',
            name='Admin',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    return ip

def can_register_from_ip(ip):
    today = datetime.datetime.utcnow().date()
    start_of_day = datetime.datetime.combine(today, datetime.time.min)
    
    count = RegistrationAttempt.query.filter(
        RegistrationAttempt.ip_address == ip,
        RegistrationAttempt.attempt_time >= start_of_day
    ).count()
    
    return count < 3

def record_registration_attempt(ip):
    attempt = RegistrationAttempt(ip_address=ip)
    db.session.add(attempt)
    db.session.commit()

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
            email = user_info.get('email', '').lower().strip()
            name = user_info.get('name', '').strip()
            picture = user_info.get('picture', '')
            
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    name=name,
                    avatar=picture if picture else '/static/logo.png'
                )
                db.session.add(user)
                db.session.commit()
            
            if user.is_banned:
                return "Ваш аккаунт заблокирован", 403
            
            login_user(user)
            session['user_id'] = user.id

# ========== ЛОКАЛЬНАЯ РЕГИСТРАЦИЯ И ВХОД ==========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.json if request.is_json else request.form
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Валидация
    if not name or not email or not password:
        return jsonify({'error': 'Заполните все поля'}), 400
    
    if len(name) < 2 or len(name) > 50:
        return jsonify({'error': 'Имя должно быть от 2 до 50 символов'}), 400
    
    if not re.match(r'^[a-zA-Z0-9@._-]+$', name):
        return jsonify({'error': 'Имя может содержать только буквы, цифры и @._-'}), 400
    
    if not re.match(r'^[^\s@]+@([^\s@]+\.)+[^\s@]+$', email):
        return jsonify({'error': 'Некорректный email'}), 400
    
    if len(password) < 4:
        return jsonify({'error': 'Пароль должен быть не менее 4 символов'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Пароли не совпадают'}), 400
    
    # Проверка на существующего пользователя
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Пользователь с таким email уже существует'}), 400
    
    # Проверка лимита регистраций с IP
    client_ip = get_client_ip()
    if not can_register_from_ip(client_ip):
        return jsonify({'error': 'С одного IP-адреса можно зарегистрировать не более 3 аккаунтов в день'}), 403
    
    # Создание пользователя
    new_user = User(
        email=email,
        name=name,
        registration_ip=client_ip
    )
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    record_registration_attempt(client_ip)
    
    # Автоматический вход после регистрации
    login_user(new_user)
    session['user_id'] = new_user.id
    
    return jsonify({'success': True, 'redirect': url_for('glavnaya')})

@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({'redirect': url_for('glavnaya')})
    
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.password_hash:
        return jsonify({'error': 'Неверный email или пароль'}), 401
    
    if not user.check_password(password):
        return jsonify({'error': 'Неверный email или пароль'}), 401
    
    if user.is_banned:
        return jsonify({'error': f'Ваш аккаунт заблокирован. Причина: {user.ban_reason}'}), 403
    
    login_user(user)
    session['user_id'] = user.id
    
    return jsonify({'success': True, 'redirect': url_for('glavnaya')})

# ========== МАРШРУТЫ ==========
@app.route('/')
def glavnaya():
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        return render_template('glavnaya.html', user=None, banned=True)
    return render_template('glavnaya.html', user=current_user if current_user.is_authenticated else None)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if 'theme' in request.form:
        current_user.theme = request.form.get('theme')
    if 'notifications' in request.form:
        current_user.notifications = request.form.get('notifications') == 'on'
    if 'sound' in request.form:
        current_user.sound = request.form.get('sound') == 'on'
    
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext in app.config['ALLOWED_EXTENSIONS']:
                filename = secure_filename(f"user_{current_user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar = f'/static/avatars/{filename}'
    
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/messages')
@login_required
def messages():
    friends = Friend.query.filter_by(user_id=current_user.id).all()
    friend_users = []
    for f in friends:
        user = User.query.get(f.friend_id)
        if user:
            friend_users.append(user)
    
    incoming_requests = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    outgoing_requests = FriendRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
    
    last_messages = []
    for friend in friend_users:
        last_msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == friend.id)) |
            ((Message.sender_id == friend.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        if last_msg:
            unread = Message.query.filter_by(sender_id=friend.id, receiver_id=current_user.id, is_read=False).count()
            last_messages.append({
                'friend': friend,
                'last_message': last_msg,
                'unread': unread
            })
    
    return render_template('messages.html',
                          user=current_user,
                          friends=friend_users,
                          incoming_requests=incoming_requests,
                          outgoing_requests=outgoing_requests,
                          last_messages=last_messages)

@app.route('/send_friend_request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'error': 'Введите email'}), 400
    
    receiver = User.query.filter(func.lower(User.email) == func.lower(email)).first()
    
    if not receiver:
        return jsonify({'error': f'Пользователь с email {email} не найден'}), 404
    
    if receiver.id == current_user.id:
        return jsonify({'error': 'Нельзя добавить самого себя'}), 400
    
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Заявка уже отправлена'}), 400
    
    existing_friend = Friend.query.filter_by(
        user_id=current_user.id,
        friend_id=receiver.id
    ).first()
    
    if existing_friend:
        return jsonify({'error': 'Уже в друзьях'}), 400
    
    friend_request = FriendRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    )
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Заявка отправлена пользователю {receiver.name}'})

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id and req.status == 'pending':
        req.status = 'accepted'
        
        existing_friend1 = Friend.query.filter_by(user_id=current_user.id, friend_id=req.sender_id).first()
        existing_friend2 = Friend.query.filter_by(user_id=req.sender_id, friend_id=current_user.id).first()
        
        if not existing_friend1:
            friend1 = Friend(user_id=current_user.id, friend_id=req.sender_id)
            db.session.add(friend1)
        
        if not existing_friend2:
            friend2 = Friend(user_id=req.sender_id, friend_id=current_user.id)
            db.session.add(friend2)
        
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/chat/<int:user_id>')
@login_required
def private_chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    is_friend = Friend.query.filter_by(user_id=current_user.id, friend_id=user_id).first()
    if not is_friend:
        return redirect(url_for('messages'))
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return render_template('private_chat.html', user=current_user, other_user=other_user, messages=messages)

@app.route('/groups')
@login_required
def groups_page():
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    group_ids = [m.group_id for m in memberships]
    groups = Group.query.filter(Group.id.in_(group_ids)).all() if group_ids else []
    
    public_groups = Group.query.filter_by(is_public=True, is_private=False).all()
    private_groups = [g for g in groups if g.is_private]
    
    return render_template('groups.html', user=current_user, groups=groups, public_groups=public_groups, private_groups=private_groups)

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership and not group.is_public:
        return redirect(url_for('groups_page'))
    
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp).all()
    
    members = GroupMember.query.filter_by(group_id=group_id).all()
    member_users = []
    for m in members:
        user = User.query.get(m.user_id)
        if user:
            member_users.append({
                'user': user,
                'is_admin': m.is_admin
            })
    
    return render_template('group_chat.html',
                          user=current_user,
                          group=group,
                          messages=messages,
                          members=member_users,
                          is_member=bool(membership))

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    name = request.form.get('name')
    description = request.form.get('description', '')
    is_private = request.form.get('is_private') == 'on'
    
    if name:
        group = Group(
            name=name,
            description=description,
            creator_id=current_user.id,
            is_private=is_private
        )
        db.session.add(group)
        db.session.commit()
        
        membership = GroupMember(
            user_id=current_user.id,
            group_id=group.id,
            is_admin=True
        )
        db.session.add(membership)
        db.session.commit()
        
        return redirect(url_for('groups_page'))
    
    return redirect(url_for('groups_page'))

@app.route('/join_group/<int:group_id>', methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if not group.is_public:
        return jsonify({'error': 'Это приватная группа'}), 403
    
    existing = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if existing:
        return jsonify({'error': 'Вы уже в группе'}), 400
    
    membership = GroupMember(user_id=current_user.id, group_id=group_id)
    db.session.add(membership)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/channels')
@login_required
def channels_page():
    memberships = ChannelMember.query.filter_by(user_id=current_user.id).all()
    channel_ids = [m.channel_id for m in memberships]
    my_channels = Channel.query.filter(Channel.id.in_(channel_ids)).all() if channel_ids else []
    
    public_channels = Channel.query.filter_by(is_public=True).all()
    
    return render_template('channels.html', user=current_user, my_channels=my_channels, public_channels=public_channels)

@app.route('/channel/<int:channel_id>')
@login_required
def channel_chat(channel_id):
    channel = Channel.query.get_or_404(channel_id)
    
    membership = ChannelMember.query.filter_by(user_id=current_user.id, channel_id=channel_id).first()
    if not membership and not channel.is_public:
        return redirect(url_for('channels_page'))
    
    messages = ChannelMessage.query.filter_by(channel_id=channel_id).order_by(ChannelMessage.timestamp).all()
    
    members = ChannelMember.query.filter_by(channel_id=channel_id).all()
    member_users = [User.query.get(m.user_id) for m in members if User.query.get(m.user_id)]
    
    return render_template('channel_chat.html',
                          user=current_user,
                          channel=channel,
                          messages=messages,
                          members=member_users,
                          is_member=bool(membership))

@app.route('/create_channel', methods=['POST'])
@login_required
def create_channel():
    name = request.form.get('name')
    description = request.form.get('description', '')
    is_public = request.form.get('is_public') == 'on'
    
    if name:
        channel = Channel(
            name=name,
            description=description,
            creator_id=current_user.id,
            is_public=is_public
        )
        db.session.add(channel)
        db.session.commit()
        
        membership = ChannelMember(
            user_id=current_user.id,
            channel_id=channel.id
        )
        db.session.add(membership)
        db.session.commit()
        
        return redirect(url_for('channels_page'))
    
    return redirect(url_for('channels_page'))

@app.route('/join_channel/<int:channel_id>', methods=['POST'])
@login_required
def join_channel(channel_id):
    channel = Channel.query.get_or_404(channel_id)
    
    if not channel.is_public:
        return jsonify({'error': 'Это приватный канал'}), 403
    
    existing = ChannelMember.query.filter_by(user_id=current_user.id, channel_id=channel_id).first()
    if existing:
        return jsonify({'error': 'Вы уже подписаны'}), 400
    
    membership = ChannelMember(user_id=current_user.id, channel_id=channel_id)
    db.session.add(membership)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('glavnaya'))
    
    users = User.query.all()
    groups = Group.query.all()
    channels = Channel.query.all()
    
    return render_template('admin.html', user=current_user, users=users, groups=groups, channels=channels)

@app.route('/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.json
    reason = data.get('reason', 'Нарушение правил')
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'Нельзя забанить администратора'}), 403
    
    user.is_banned = True
    user.ban_reason = reason
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/unban_user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/login/google')
def google_login():
    return redirect(url_for("google.login"))

@app.route('/logout')
@app.route('/vyhod')
def vyhod():
    logout_user()
    session.clear()
    return redirect(url_for('glavnaya'))

# ========== WEBSOCKET СОБЫТИЯ ==========
@socketio.on('send_private_message')
def handle_private_message(data):
    sender = User.query.get(data['sender_id'])
    receiver = User.query.get(data['receiver_id'])
    
    if not sender or not receiver:
        return
    
    msg = Message(
        sender_id=data['sender_id'],
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    db.session.add(msg)
    db.session.commit()
    
    room = f"private_{min(data['sender_id'], data['receiver_id'])}_{max(data['sender_id'], data['receiver_id'])}"
    
    emit('new_private_message', {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': sender.name,
        'sender_avatar': sender.avatar,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room=room)

@socketio.on('join_private_chat')
def join_private_chat(data):
    user1 = data['user1']
    user2 = data['user2']
    room = f"private_{min(user1, user2)}_{max(user1, user2)}"
    join_room(room)

@socketio.on('send_group_message')
def handle_group_message(data):
    user = User.query.get(data['user_id'])
    group = Group.query.get(data['group_id'])
    
    if not user or not group:
        return
    
    msg = GroupMessage(
        user_id=data['user_id'],
        group_id=data['group_id'],
        content=data['content']
    )
    db.session.add(msg)
    db.session.commit()
    
    room = f"group_{data['group_id']}"
    
    emit('new_group_message', {
        'id': msg.id,
        'user_id': msg.user_id,
        'user_name': user.name,
        'user_avatar': user.avatar,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room=room)

@socketio.on('join_group_chat')
def join_group_chat(data):
    room = f"group_{data['group_id']}"
    join_room(room)

@socketio.on('send_channel_message')
def handle_channel_message(data):
    user = User.query.get(data['user_id'])
    channel = Channel.query.get(data['channel_id'])
    
    if not user or not channel:
        return
    
    msg = ChannelMessage(
        user_id=data['user_id'],
        channel_id=data['channel_id'],
        content=data['content']
    )
    db.session.add(msg)
    db.session.commit()
    
    room = f"channel_{data['channel_id']}"
    
    emit('new_channel_message', {
        'id': msg.id,
        'user_id': msg.user_id,
        'user_name': user.name,
        'user_avatar': user.avatar,
        'content': msg.content,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room=room)

@socketio.on('join_channel')
def join_channel(data):
    room = f"channel_{data['channel_id']}"
    join_room(room)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
