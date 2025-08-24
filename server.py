# server.py
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "secret!")
# Force gevent async mode
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

ROOMS = {}  # room_name -> set(socket_id)

@app.route("/")
def index():
    return render_template("index.html")

# Client tells server: join a room
@socketio.on("join")
def on_join(data):
    room = data.get("room", "default-room")
    name = data.get("name", "")
    sid = request.sid

    join_room(room)
    ROOMS.setdefault(room, set()).add(sid)

    # send back list of other members in the room (so client can initiate offers)
    others = [s for s in ROOMS.get(room, set()) if s != sid]
    emit("joined", {"you": sid, "others": others})

    # notify others about the newcomer
    emit("new-peer", {"peer": sid}, room=room, include_self=False)

@socketio.on("leave")
def on_leave(data):
    room = data.get("room", "default-room")
    sid = request.sid
    leave_room(room)
    s = ROOMS.get(room, set())
    if sid in s:
        s.remove(sid)
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
    # Remove from any rooms
    for room, members in list(ROOMS.items()):
        if sid in members:
            members.remove(sid)
            emit("peer-left", {"peer": sid}, room=room)

if __name__ == "__main__":
    # Use gevent WSGI server provided by flask-socketio
    socketio.run(app, host="0.0.0.0", port=5000)

