# server.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "secret!")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Force gevent async mode
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

ROOMS = {}  # room_name -> set(socket_id)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    logger.info(f"Home page accessed - User authenticated: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        logger.info(f"User '{current_user.username}' accessing broadcast page")
        return render_template("broadcast.html")
    logger.info("Redirecting unauthenticated user to login")
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logger.info(f"Already authenticated user '{current_user.username}' redirected to home")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for username: {username}")
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            logger.info(f"Successful login for user: {username}")
            flash('Logged in successfully!', 'success')
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
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"Successful registration for user: {username}")
        flash('Registration successful! Please login.', 'success')
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

if __name__ == "__main__":
    logger.info("Starting Broadcast App Server...")
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully")
    
    logger.info("Server starting on http://0.0.0.0:5000")
    # Use gevent WSGI server provided by flask-socketio
    socketio.run(app, host="0.0.0.0", port=5000)

