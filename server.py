# server.py
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
from collections import defaultdict
import boto3
from botocore.exceptions import ClientError
import urllib.parse
from dotenv import load_dotenv
from datetime import datetime, timedelta
import threading

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "secret!")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging (single file, no backups)
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Prune app.log to keep only the last 5 hours of entries (no backups)
PRUNE_INTERVAL_SECONDS = 3600  # run hourly
KEEP_HOURS = 5

def _parse_log_time(line: str):
    # Expect lines starting with: 'YYYY-MM-DD HH:MM:SS,mmm - ...'
    try:
        ts = line.split(' - ', 1)[0]
        # Example: 2025-09-01 20:29:29,448
        return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S,%f')
    except Exception:
        return None

def prune_app_log():
    try:
        if not os.path.exists('app.log'):
            return
        cutoff = datetime.now() - timedelta(hours=KEEP_HOURS)
        with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        kept = []
        for line in lines:
            dt = _parse_log_time(line)
            if dt is None or dt >= cutoff:
                kept.append(line)
        with open('app.log', 'w', encoding='utf-8') as f:
            f.writelines(kept)
    except Exception as e:
        # Do not crash on pruning errors
        logging.getLogger(__name__).warning(f'Log prune failed: {e}')

_defuse = {'timer': None}

def _schedule_prune():
    prune_app_log()
    t = threading.Timer(PRUNE_INTERVAL_SECONDS, _schedule_prune)
    t.daemon = True
    t.start()
    _defuse['timer'] = t

# Start pruning loop once at import time
_schedule_prune()

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'eu-north-1')
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'soothing-playlist')

# Initialize S3 client if credentials are available
s3_client = None
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        logger.info(f"AWS S3 client initialized for bucket: {S3_BUCKET_NAME}")
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {e}")
else:
    logger.warning("AWS credentials not found. S3 functionality will be disabled.")

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Force gevent async mode
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

ROOMS = {}  # room_name -> set(socket_id)
CHAT_HISTORY = defaultdict(list)  # room_name -> [{user, message}]
MAX_CHAT_HISTORY = 1000

# Synchronized room playback state (in-memory)
# CURRENT_SONG = {}  # room -> { 'song_name': str, 's3_key': str, 'started_at': float, 'started_by': str }

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    # Admin approval flags
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    logger.info(f"Home page accessed - User authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        if getattr(current_user, 'is_admin', False):
            logger.info(f"Admin '{current_user.username}' redirected to admin dashboard")
            return redirect(url_for('admin_dashboard'))
        logger.info(f"User '{current_user.username}' accessing broadcast page")
        return render_template("broadcast.html")
    logger.info("Redirecting unauthenticated user to login")
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logger.info(f"Already authenticated user '{current_user.username}' redirected appropriately")
        if getattr(current_user, 'is_admin', False):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for username: {username}")
        
        user = User.query.filter_by(username=username).first()
        print("#123456789", user)
        if user and user.check_password(password):
            if not user.is_approved:
                logger.warning(f"Login blocked for unapproved user: {username}")
                flash('Your account is pending approval by an administrator.', 'error')
                return render_template("login.html")
            login_user(user)
            logger.info(f"Successful login for user: {username}")
            flash('Logged in successfully!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'error')
    else:
        logger.info("Login page accessed")
    
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        logger.info(f"Already authenticated user '{current_user.username}' redirected to home")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        logger.info(f"Registration attempt for username: {username}, email: {email}")
        
        if password != confirm_password:
            logger.warning(f"Registration failed for {username}: Passwords do not match")
            flash('Passwords do not match!', 'error')
            return render_template("register.html")
        
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration failed for {username}: Username already exists")
            flash('Username already exists!', 'error')
            return render_template("register.html")
        
        if User.query.filter_by(email=email).first():
            logger.warning(f"Registration failed for {username}: Email already registered")
            flash('Email already registered!', 'error')
            return render_template("register.html")
        
        user = User(username=username, email=email, is_approved=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"Successful registration for user: {username} (awaiting approval)")
        flash('Registration successful! Please wait for admin approval before logging in.', 'success')
        return redirect(url_for('login'))
    else:
        logger.info("Registration page accessed")
    
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User '{username}' logged out")
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# Admin dashboard and actions
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    pending_users = User.query.filter_by(is_approved=False).all()
    approved_users = User.query.filter_by(is_approved=True).all()
    # Get all messages from all rooms
    all_messages = []
    for room, messages in CHAT_HISTORY.items():
        for i, msg in enumerate(messages):
            all_messages.append({
                'room': room,
                'index': i,
                'user': msg['user'],
                'message': msg['message']
            })
    # Sort by room and message order
    all_messages.sort(key=lambda x: (x['room'], x['index']))
    return render_template('admin.html', pending_users=pending_users, approved_users=approved_users, all_messages=all_messages)

@app.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot change approval for admin users.', 'error')
        return redirect(url_for('admin_dashboard'))
    user.is_approved = True
    db.session.commit()
    logger.info(f"Admin '{current_user.username}' approved user '{user.username}'")
    flash(f"Approved user '{user.username}'", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot reject admin users.', 'error')
        return redirect(url_for('admin_dashboard'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    logger.info(f"Admin '{current_user.username}' rejected (deleted) user '{username}'")
    flash(f"Rejected and removed user '{username}'", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_message/<int:message_index>', methods=['POST'])
@login_required
@admin_required
def delete_message(message_index):
    room = request.form.get('room', 'DEV-DANK')
    if room in CHAT_HISTORY and 0 <= message_index < len(CHAT_HISTORY[room]):
        deleted_msg = CHAT_HISTORY[room].pop(message_index)
        logger.info(f"Admin '{current_user.username}' deleted message from '{deleted_msg['user']}': {deleted_msg['message']}")
        flash(f"Deleted message from {deleted_msg['user']}", 'success')
    else:
        flash('Message not found', 'error')
    return redirect(url_for('admin_dashboard'))

# Client tells server: join a room
@socketio.on("join")
@login_required
def on_join(data):
    room = data.get("room", "default-room")
    name = data.get("name", current_user.username)
    sid = request.sid

    logger.info(f"User '{current_user.username}' (SID: {sid}) joining room: {room}")
    
    join_room(room)
    ROOMS.setdefault(room, set()).add(sid)

    # send back list of other members in the room (so client can initiate offers)
    others = [s for s in ROOMS.get(room, set()) if s != sid]
    logger.info(f"Room '{room}' now has {len(ROOMS[room])} users. Others: {len(others)}")
    emit("joined", {"you": sid, "others": others})

    # notify others about the newcomer
    emit("new-peer", {"peer": sid, "name": name}, room=room, include_self=False)

@socketio.on("leave")
def on_leave(data):
    room = data.get("room", "default-room")
    sid = request.sid
    
    logger.info(f"User (SID: {sid}) leaving room: {room}")
    
    leave_room(room)
    s = ROOMS.get(room, set())
    if sid in s:
        s.remove(sid)
        logger.info(f"Room '{room}' now has {len(s)} users")
    emit("peer-left", {"peer": sid}, room=room)

# Relay offer/answer/ice to a specific peer
@socketio.on("signal")
def on_signal(data):
    # data: { to: targetSid, from: mySid, type: 'offer'/'answer'/'candidate', sdp/candidate: ... }
    target = data.get("to")
    if not target:
        return
    emit("signal", data, room=target)

@socketio.on("chat")
@login_required
def on_chat(data):
    room = data.get("room")
    message = (data.get("message") or "").strip()
    if not room or not message:
        return
    logger.info(f"Chat in '{room}' from '{current_user.username}': {message}")
    # Append to history
    CHAT_HISTORY[room].append({"user": current_user.username, "message": message})
    if len(CHAT_HISTORY[room]) > MAX_CHAT_HISTORY:
        del CHAT_HISTORY[room][:-MAX_CHAT_HISTORY]
    # Broadcast to others only
    emit("chat", {"user": current_user.username, "message": message}, room=room, include_self=False)

@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    logger.info(f"User disconnected (SID: {sid})")
    
    # Remove from any rooms
    for room, members in list(ROOMS.items()):
        if sid in members:
            members.remove(sid)
            logger.info(f"Removed user from room '{room}'. Room now has {len(members)} users")
            emit("peer-left", {"peer": sid}, room=room)

# @socketio.on("play_song")
# @login_required
# def on_play_song(data):
#     room = data.get("room")
#     song_name = data.get("song_name")
#     s3_key = data.get("s3_key")
#     if not room or not song_name or not s3_key:
#         return
#     import time as _time
#     CURRENT_SONG[room] = {
#         "song_name": song_name,
#         "s3_key": s3_key,
#         "started_at": _time.time(),
#         "started_by": current_user.username,
#     }
#     logger.info(f"Song started in room '{room}': {song_name} by {current_user.username}")
#     emit("song_started", CURRENT_SONG[room], room=room)

# @socketio.on("sync_song")
# @login_required
# def on_sync_song(data):
#     room = data.get("room")
#     if not room:
#         return
#     state = CURRENT_SONG.get(room)
#     if state:
#         # send only to requester
#         emit("song_started", state)

# # On chat join, also push current song (if any) to the newly joined user
@socketio.on("join_chat")
@login_required
def on_join_chat(data):
    room = data.get("room", "default-room")
    name = data.get("name", current_user.username)
    sid = request.sid
    join_room(room)
    logger.info(f"[CHAT] User '{current_user.username}' (SID: {sid}) joined chat room: {room}")
    # Send recent history to the joining client only
    emit("chat_history", {"messages": CHAT_HISTORY[room][-MAX_CHAT_HISTORY:]})
    # # Send current song state if any (only to this client)
    # state = CURRENT_SONG.get(room)
    # if state:
    #     emit("song_started", state)

@socketio.on("leave_chat")
@login_required
def on_leave_chat(data):
    room = data.get("room", "default-room")
    sid = request.sid
    leave_room(room)
    logger.info(f"[CHAT] User (SID: {sid}) left chat room: {room}")

# Music API endpoints
@app.route('/api/songs')
@login_required
def get_songs():
    """Get list of songs from S3 bucket"""
    if not s3_client:
        logger.warning("S3 client not available")
        return jsonify([])
    
    try:
        logger.info(f"Fetching songs from S3 bucket: {S3_BUCKET_NAME}")
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME)
        
        songs = []
        if 'Contents' in response:
            for obj in response['Contents']:
                # Skip directories and non-audio files
                if obj['Key'].endswith('/') or not any(obj['Key'].lower().endswith(ext) for ext in ['.mp3', '.wav', '.m4a', '.flac']):
                    continue
                
                # Decode URL-encoded filename
                song_name = urllib.parse.unquote(obj['Key'])
                songs.append({
                    'name': song_name,
                    's3_key': obj['Key'],
                    'size': obj['Size']
                })
        
        logger.info(f"Returning {len(songs)} songs")
        return jsonify(songs)
        
    except ClientError as e:
        logger.error(f"S3 error: {e}")
        return jsonify([])
    except Exception as e:
        logger.error(f"Error fetching songs: {e}")
        return jsonify([])

@app.route('/stream/<path:s3_key>')
@login_required
def stream_song(s3_key):
    """Generate presigned URL for streaming a song from S3"""
    if not s3_client:
        logger.warning("S3 client not available for streaming")
        abort(404)
    
    try:
        # Decode the S3 key
        decoded_key = urllib.parse.unquote(s3_key)
        logger.info(f"Generating presigned URL for: {decoded_key}")
        
        # Generate presigned URL for streaming
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET_NAME, 'Key': decoded_key},
            ExpiresIn=3600  # 1 hour
        )
        
        return redirect(presigned_url)
        
    except ClientError as e:
        logger.error(f"S3 streaming error: {e}")
        abort(404)
    except Exception as e:
        logger.error(f"Error generating presigned URL: {e}")
        abort(404)

def _ensure_schema_and_seed_admin():
    # Add columns to existing SQLite table if missing
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('user')]
        with db.engine.begin() as conn:
            if 'is_admin' not in columns:
                conn.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0"))
                logger.info("Added column is_admin to user table")
            if 'is_approved' not in columns:
                conn.execute(text("ALTER TABLE user ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT 0"))
                logger.info("Added column is_approved to user table")
    except Exception as e:
        logger.error(f"Schema ensure error: {e}")

    # Seed admin user from env, or default credentials
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')

    admin = User.query.filter((User.username == admin_username) | (User.email == admin_email)).first()
    if not admin:
        admin = User(username=admin_username, email=admin_email, is_admin=True, is_approved=True)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        logger.warning(f"Seeded default admin user '{admin_username}'. Change the password immediately.")
    else:
        # Ensure flags are set on existing admin
        if not admin.is_admin or not admin.is_approved:
            admin.is_admin = True
            admin.is_approved = True
            db.session.commit()
            logger.info("Ensured existing admin has admin/approved flags set")

if __name__ == "__main__":
    logger.info("Starting Broadcast App Server...")
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully")
        _ensure_schema_and_seed_admin()
    
    logger.info("Server starting on http://0.0.0.0:5000")
    # Use gevent WSGI server provided by flask-socketio
    socketio.run(app, host="0.0.0.0", port=5000)

