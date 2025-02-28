from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from db import User  # Import User model from db.py
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from dotenv import load_dotenv
import threading
import time


load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    if User.objects(email=email).first():
        return jsonify({'message': 'User already exists!'}), 400

    hashed_password = generate_password_hash(password)
    user = User(name=name, email=email, password=hashed_password)
    user.save()
    return jsonify({'message': 'User created successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.objects(email=email).first()
    if user and check_password_hash(user.password, password):
        token = jwt.encode(
            {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return jsonify({'message': 'Login successful!', 'token': token}), 200
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/bot', methods=['POST'])
def bot():
    message = request.form.get('message')
    if message:
        return jsonify({'message': 'Bot is not working!'}), 200
    
@app.route('/sumrize', methods=['GET'])
def sumrize():
    return jsonify({'message': 'Sumrize is not working!'}), 200


def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.objects(email=data['email']).first()
        except:
            return jsonify({'message': 'Invalid or expired token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/secure-route', methods=['GET'])
@token_required
def secure_route(current_user):
    return jsonify({'message': f'Welcome {current_user.name}!', 'email': current_user.email , 'username' :current_user.name})

online_users = {}
chat_messages = []

@socketio.on('connect')
def handle_connect():
    # Add user to online users
    session_id = request.sid
    online_users[session_id] = True
    print(f"User connected: {session_id}")

    emit('online_users', {'count': len(online_users)}, broadcast=True)
    emit('chat_history', {'messages': chat_messages}, room=session_id)

@socketio.on('disconnect')
def handle_disconnect():
    # Remove user from online users
    session_id = request.sid
    if session_id in online_users:
        del online_users[session_id]
    print(f"User disconnected: {session_id}")

    # Broadcast updated online user count
    emit('online_users', {'count': len(online_users)}, broadcast=True)

    # Delete all messages if no users are online
    if len(online_users) == 0:
        chat_messages.clear()
        print("No users online. All messages deleted.")

@socketio.on('chat')
def handle_chat(data):
    message = data.get('message')
    username = data.get('username')
    if message and username:
        formatted_message = {'username': username, 'message': message, 'timestamp': str(datetime.datetime.now())}
        chat_messages.append(formatted_message)  # Save the message
        emit('message', formatted_message, broadcast=True)  # Broadcast the message
        if message[0] == '@':
            bot_message = {'username': "BOT", 'message': 'Hello, the bot is not working.', 'timestamp': str(datetime.datetime.now())}
            emit('message', bot_message, broadcast=True)  # Broadcast the bot message




if __name__ == '__main__':
    socketio.run(app, debug=True)
