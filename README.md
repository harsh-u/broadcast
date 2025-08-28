# Broadcast App with Authentication

A real-time audio broadcasting application with user authentication built with Flask, WebRTC, and Socket.IO.

## Features

- 🔐 User authentication (login/register)
- 🎙️ Real-time audio broadcasting
- 👥 Multi-user rooms
- 🔇 Mute/unmute functionality
- 📱 Responsive design
- 🔒 Secure password hashing
- 💾 SQLite database for user management

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. **Clone or download the project files**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python server.py
   ```

4. **Open your browser and navigate to:**
   ```
   http://localhost:5000
   ```

## Usage

### First Time Setup

1. **Register a new account:**
   - Click "Register here" on the login page
   - Fill in your username, email, and password
   - Click "Create Account"

2. **Login:**
   - Enter your username and password
   - Click "Sign In"

### Broadcasting

1. **Join a room:**
   - Enter a room name (or use the default "demo-room")
   - Your display name will be pre-filled with your username
   - Click "Join Room"
   - Allow microphone access when prompted

2. **Start broadcasting:**
   - Click the "🎙️ Unmute" button to start broadcasting your audio
   - Other users in the same room will hear your audio
   - Click "🔇 Mute" to stop broadcasting

3. **Leave the room:**
   - Click "Leave" to disconnect from the room

### Multi-User Broadcasting

- Multiple users can join the same room
- Each user will see other participants as audio tiles
- Connection status is indicated by colored dots (green = connected, red = disconnected)
- Users can mute/unmute independently

## File Structure

```
broadcast/
├── server.py              # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── broadcast.html    # Main broadcasting interface
└── users.db              # SQLite database (created automatically)
```

## Technical Details

### Backend
- **Flask**: Web framework
- **Flask-SocketIO**: WebSocket support for real-time communication
- **Flask-Login**: User session management
- **Flask-SQLAlchemy**: Database ORM
- **Werkzeug**: Password hashing and security

### Frontend
- **WebRTC**: Peer-to-peer audio streaming
- **Socket.IO**: Real-time communication
- **Modern CSS**: Responsive design with gradients and animations

### Security Features
- Password hashing using Werkzeug
- Session management with Flask-Login
- CSRF protection
- Secure cookie handling

## Troubleshooting

### Common Issues

1. **Microphone not working:**
   - Ensure your browser has permission to access the microphone
   - Check if your microphone is properly connected and working
   - Try refreshing the page and allowing microphone access again

2. **Can't hear other users:**
   - Check if other users have unmuted their microphones
   - Verify you're in the same room as other users
   - Check your system audio settings

3. **Connection issues:**
   - Ensure you have a stable internet connection
   - Check if the server is running properly
   - Try refreshing the page

4. **Database errors:**
   - Delete the `users.db` file and restart the server
   - The database will be recreated automatically

### Browser Compatibility

This application works best with modern browsers that support WebRTC:
- Chrome (recommended)
- Firefox
- Safari
- Edge

## Development

To run in development mode with auto-reload:

```bash
export FLASK_ENV=development
python server.py
```

## License

This project is open source and available under the MIT License.
