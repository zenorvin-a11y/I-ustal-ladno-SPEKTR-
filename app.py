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
from sqlalchemy import or_, func

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

# ========== МОДЕЛИ ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default='/static/logo.png')
    theme = db.Column(db.String(20), default='light')
    notifications = db.Column(db.Boolean, default=True)
    sound = db.Column(db.Boolean, default=True)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver')
    group_memberships = db.relationship('GroupMember', back_populates='user')
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', back_populates='sender')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', back_populates='receiver')
    friends_list = db.relationship('Friend', foreign_keys='Friend.user_id', back_populates='user')

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

with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            email='admin@spektr.ru',
            name='Admin',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

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
                print(f"✅ Новый пользователь создан: {email}")
            
            if user.is_banned:
                return "Ваш аккаунт заблокирован", 403
            
            login_user(user)
            session['user_id'] = user.id
            print(f"✅ Вход выполнен: {email}")

# ========== МАРШРУТЫ ==========
@app.route('/')
def glavnaya():
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        return render_template('glavnaya.html', user=None, banned=True)
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
def messages():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    # Получаем друзей
    friends = Friend.query.filter_by(user_id=current_user.id).all()
    friend_users = []
    for f in friends:
        user = User.query.get(f.friend_id)
        if user:
            friend_users.append(user)
    
    # Получаем заявки
    incoming_requests = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    outgoing_requests = FriendRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
    
    # Получаем последние сообщения
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
def send_friend_request():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'error': 'Введите email'}), 400
    
    # Ищем пользователя по email (без учёта регистра)
    receiver = User.query.filter(func.lower(User.email) == func.lower(email)).first()
    
    if not receiver:
        # Для отладки - покажем все email в базе
        all_users = User.query.all()
        emails = [u.email for u in all_users]
        print(f"Поиск: {email}, Найдено пользователей: {len(all_users)}")
        print(f"Emails в базе: {emails}")
        return jsonify({'error': f'Пользователь с email {email} не найден'}), 404
    
    if receiver.id == current_user.id:
        return jsonify({'error': 'Нельзя добавить самого себя'}), 400
    
    # Проверяем, есть ли уже заявка
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Заявка уже отправлена'}), 400
    
    # Проверяем, не друзья ли уже
    existing_friend = Friend.query.filter_by(
        user_id=current_user.id,
        friend_id=receiver.id
    ).first()
    
    if existing_friend:
        return jsonify({'error': 'Уже в друзьях'}), 400
    
    # Всё хорошо, создаём заявку
    friend_request = FriendRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    )
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Заявка отправлена пользователю {receiver.name}'})

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id:
        req.status = 'accepted'
        
        friend1 = Friend(user_id=current_user.id, friend_id=req.sender_id)
        friend2 = Friend(user_id=req.sender_id, friend_id=current_user.id)
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/chat/<int:user_id>')
def private_chat(user_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
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
        return jsonify({'success': True, 'timestamp': msg.timestamp.strftime('%H:%M')})
    
    return jsonify({'error': 'Invalid data'}), 400

@app.route('/obshchenie')
def obshchenie():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    group_ids = [m.group_id for m in memberships]
    groups = Group.query.filter(Group.id.in_(group_ids)).all() if group_ids else []
    
    return render_template('obshchenie.html', user=current_user, groups=groups)

@app.route('/group/<int:group_id>')
def group_chat(group_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    group = Group.query.get_or_404(group_id)
    
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        return redirect(url_for('obshchenie'))
    
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
    
    all_users = []
    if membership.is_admin:
        existing_ids = [m.user_id for m in members]
        all_users = User.query.filter(
            User.id != current_user.id,
            ~User.id.in_(existing_ids) if existing_ids else True
        ).all()
    
    return render_template('group_chat.html',
                          user=current_user,
                          group=group,
                          messages=messages,
                          members=member_users,
                          all_users=all_users,
                          is_admin=membership.is_admin)

@app.route('/update_group/<int:group_id>', methods=['POST'])
def update_group(group_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    group = Group.query.get_or_404(group_id)
    
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id, is_admin=True).first()
    if not membership:
        return jsonify({'error': 'Permission denied'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    is_public = request.form.get('is_public') == 'on'
    
    if name:
        group.name = name
    if description is not None:
        group.description = description
    group.is_public = is_public
    
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext in app.config['ALLOWED_EXTENSIONS']:
                filename = secure_filename(f"group_{group.id}_{file.filename}")
                file.save(os.path.join(app.config['GROUP_UPLOAD_FOLDER'], filename))
                group.avatar = f'/static/group_avatars/{filename}'
    
    db.session.commit()
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/add_to_group', methods=['POST'])
def add_to_group():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    group_id = data.get('group_id')
    user_id = data.get('user_id')
    
    if group_id and user_id:
        membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
        if membership and membership.is_admin:
            existing = GroupMember.query.filter_by(user_id=user_id, group_id=group_id).first()
            if not existing:
                new_member = GroupMember(user_id=user_id, group_id=group_id)
                db.session.add(new_member)
                db.session.commit()
                return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/remove_from_group', methods=['POST'])
def remove_from_group():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    group_id = data.get('group_id')
    user_id = data.get('user_id')
    
    if group_id and user_id:
        membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
        if membership and membership.is_admin:
            to_remove = GroupMember.query.filter_by(user_id=user_id, group_id=group_id).first()
            if to_remove:
                db.session.delete(to_remove)
                db.session.commit()
                return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

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
        return jsonify({'success': True, 'timestamp': msg.timestamp.strftime('%H:%M')})
    
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

@app.route('/admin')
def admin_panel():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('glavnaya'))
    
    users = User.query.all()
    groups = Group.query.all()
    
    return render_template('admin.html', user=current_user, users=users, groups=groups)

@app.route('/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.json
    reason = data.get('reason', 'Нарушение правил')
    
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    user.ban_reason = reason
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/unban_user/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()
    
    return jsonify({'success': True})

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
    app.run(host='0.0.0.0', port=port)import os
import sys
import datetime
import traceback
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from werkzeug.utils import secure_filename
from sqlalchemy import or_, func

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

# ========== МОДЕЛИ ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default='/static/logo.png')
    theme = db.Column(db.String(20), default='light')
    notifications = db.Column(db.Boolean, default=True)
    sound = db.Column(db.Boolean, default=True)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', back_populates='receiver')
    group_memberships = db.relationship('GroupMember', back_populates='user')
    sent_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', back_populates='sender')
    received_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', back_populates='receiver')
    friends_list = db.relationship('Friend', foreign_keys='Friend.user_id', back_populates='user')

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

with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            email='admin@spektr.ru',
            name='Admin',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

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
                print(f"✅ Новый пользователь создан: {email}")
            
            if user.is_banned:
                return "Ваш аккаунт заблокирован", 403
            
            login_user(user)
            session['user_id'] = user.id
            print(f"✅ Вход выполнен: {email}")

# ========== МАРШРУТЫ ==========
@app.route('/')
def glavnaya():
    if current_user.is_authenticated and current_user.is_banned:
        logout_user()
        return render_template('glavnaya.html', user=None, banned=True)
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
def messages():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    # Получаем друзей
    friends = Friend.query.filter_by(user_id=current_user.id).all()
    friend_users = []
    for f in friends:
        user = User.query.get(f.friend_id)
        if user:
            friend_users.append(user)
    
    # Получаем заявки
    incoming_requests = FriendRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()
    outgoing_requests = FriendRequest.query.filter_by(sender_id=current_user.id, status='pending').all()
    
    # Получаем последние сообщения
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
def send_friend_request():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'error': 'Введите email'}), 400
    
    # Ищем пользователя по email (без учёта регистра)
    receiver = User.query.filter(func.lower(User.email) == func.lower(email)).first()
    
    if not receiver:
        # Для отладки - покажем все email в базе
        all_users = User.query.all()
        emails = [u.email for u in all_users]
        print(f"Поиск: {email}, Найдено пользователей: {len(all_users)}")
        print(f"Emails в базе: {emails}")
        return jsonify({'error': f'Пользователь с email {email} не найден'}), 404
    
    if receiver.id == current_user.id:
        return jsonify({'error': 'Нельзя добавить самого себя'}), 400
    
    # Проверяем, есть ли уже заявка
    existing_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'error': 'Заявка уже отправлена'}), 400
    
    # Проверяем, не друзья ли уже
    existing_friend = Friend.query.filter_by(
        user_id=current_user.id,
        friend_id=receiver.id
    ).first()
    
    if existing_friend:
        return jsonify({'error': 'Уже в друзьях'}), 400
    
    # Всё хорошо, создаём заявку
    friend_request = FriendRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        status='pending'
    )
    db.session.add(friend_request)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Заявка отправлена пользователю {receiver.name}'})

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id:
        req.status = 'accepted'
        
        friend1 = Friend(user_id=current_user.id, friend_id=req.sender_id)
        friend2 = Friend(user_id=req.sender_id, friend_id=current_user.id)
        
        db.session.add(friend1)
        db.session.add(friend2)
        db.session.commit()
        
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    req = FriendRequest.query.get_or_404(request_id)
    
    if req.receiver_id == current_user.id:
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/chat/<int:user_id>')
def private_chat(user_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
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
        return jsonify({'success': True, 'timestamp': msg.timestamp.strftime('%H:%M')})
    
    return jsonify({'error': 'Invalid data'}), 400

@app.route('/obshchenie')
def obshchenie():
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    group_ids = [m.group_id for m in memberships]
    groups = Group.query.filter(Group.id.in_(group_ids)).all() if group_ids else []
    
    return render_template('obshchenie.html', user=current_user, groups=groups)

@app.route('/group/<int:group_id>')
def group_chat(group_id):
    if not current_user.is_authenticated:
        return redirect(url_for('glavnaya'))
    
    group = Group.query.get_or_404(group_id)
    
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        return redirect(url_for('obshchenie'))
    
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
    
    all_users = []
    if membership.is_admin:
        existing_ids = [m.user_id for m in members]
        all_users = User.query.filter(
            User.id != current_user.id,
            ~User.id.in_(existing_ids) if existing_ids else True
        ).all()
    
    return render_template('group_chat.html',
                          user=current_user,
                          group=group,
                          messages=messages,
                          members=member_users,
                          all_users=all_users,
                          is_admin=membership.is_admin)

@app.route('/update_group/<int:group_id>', methods=['POST'])
def update_group(group_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    group = Group.query.get_or_404(group_id)
    
    membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id, is_admin=True).first()
    if not membership:
        return jsonify({'error': 'Permission denied'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    is_public = request.form.get('is_public') == 'on'
    
    if name:
        group.name = name
    if description is not None:
        group.description = description
    group.is_public = is_public
    
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext in app.config['ALLOWED_EXTENSIONS']:
                filename = secure_filename(f"group_{group.id}_{file.filename}")
                file.save(os.path.join(app.config['GROUP_UPLOAD_FOLDER'], filename))
                group.avatar = f'/static/group_avatars/{filename}'
    
    db.session.commit()
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/add_to_group', methods=['POST'])
def add_to_group():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    group_id = data.get('group_id')
    user_id = data.get('user_id')
    
    if group_id and user_id:
        membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
        if membership and membership.is_admin:
            existing = GroupMember.query.filter_by(user_id=user_id, group_id=group_id).first()
            if not existing:
                new_member = GroupMember(user_id=user_id, group_id=group_id)
                db.session.add(new_member)
                db.session.commit()
                return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

@app.route('/remove_from_group', methods=['POST'])
def remove_from_group():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    group_id = data.get('group_id')
    user_id = data.get('user_id')
    
    if group_id and user_id:
        membership = GroupMember.query.filter_by(user_id=current_user.id, group_id=group_id).first()
        if membership and membership.is_admin:
            to_remove = GroupMember.query.filter_by(user_id=user_id, group_id=group_id).first()
            if to_remove:
                db.session.delete(to_remove)
                db.session.commit()
                return jsonify({'success': True})
    
    return jsonify({'error': 'Permission denied'}), 403

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
        return jsonify({'success': True, 'timestamp': msg.timestamp.strftime('%H:%M')})
    
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

@app.route('/admin')
def admin_panel():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('glavnaya'))
    
    users = User.query.all()
    groups = Group.query.all()
    
    return render_template('admin.html', user=current_user, users=users, groups=groups)

@app.route('/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.json
    reason = data.get('reason', 'Нарушение правил')
    
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    user.ban_reason = reason
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/unban_user/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify({'error': 'Permission denied'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    user.ban_reason = None
    db.session.commit()
    
    return jsonify({'success': True})

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
