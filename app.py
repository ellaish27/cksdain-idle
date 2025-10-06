from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import uuid
import subprocess
import sys
import os
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# In-memory data storage (in production, use a database)
workspaces = {}
users = {}  # Stores user tokens with registration status
user_credentials = {}  # Stores username/password credentials
admin_tokens = {}

# Create default admin
default_admin_token = secrets.token_urlsafe(16)
admin_tokens[default_admin_token] = True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/<token>')
def login_with_token(token):
    if token in admin_tokens:
        session['is_admin'] = True
        session['user_id'] = f"admin_{uuid.uuid4().hex[:6]}"
        session['username'] = "Admin"
        session['color'] = "#FF6F61"  # Admin accent color
        return redirect(url_for('workspace'))
    elif token in users:
        # Check if user has already registered
        if users[token].get('registered', False):
            flash('You have already registered. Please log in with your credentials.')
            return redirect(url_for('index'))
        else:
            # User needs to register
            return redirect(url_for('register', token=token))
    else:
        return "Invalid login link", 404

@app.route('/register/<token>', methods=['GET', 'POST'])
def register(token):
    if token not in users:
        return "Invalid registration token", 404
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required')
            return render_template('register.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html', token=token)
        
        # Check if username already exists
        if username in user_credentials:
            flash('Username already taken')
            return render_template('register.html', token=token)
        
        # Hash password and store credentials
        password_hash = generate_password_hash(password)
        user_credentials[username] = {
            'password_hash': password_hash,
            'color': users[token]['color'],
            'created_at': datetime.now().isoformat()
        }
        
        # Mark token as registered
        users[token]['registered'] = True
        users[token]['username'] = username
        
        # Log the user in
        session['user_id'] = users[token]['user_id']
        session['username'] = username
        session['color'] = users[token]['color']
        
        flash('Registration successful! You are now logged in.')
        return redirect(url_for('workspace'))
    
    return render_template('register.html', token=token)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password are required')
        return redirect(url_for('index'))
    
    if username not in user_credentials:
        flash('Invalid username or password')
        return redirect(url_for('index'))
    
    if check_password_hash(user_credentials[username]['password_hash'], password):
        session['user_id'] = f"user_{uuid.uuid4().hex[:6]}"
        session['username'] = username
        session['color'] = user_credentials[username]['color']
        return redirect(url_for('workspace'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

@app.route('/workspace')
def workspace():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    workspace_id = session.get('workspace_id', 'default_workspace')
    if workspace_id not in workspaces:
        workspaces[workspace_id] = {
            'code': '# Welcome to CKS_D@in Collaborative IDE\nprint("Hello, World!")',
            'users': {},
            'chat': []
        }
    
    return render_template('workspace.html', 
                          workspace_id=workspace_id,
                          username=session['username'],
                          user_color=session['color'],
                          is_admin=session.get('is_admin', False))

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    return render_template('admin.html', 
                          admin_link=f"{request.host_url}login/{default_admin_token}",
                          users=users,
                          user_credentials=user_credentials)

@app.route('/create_user', methods=['POST'])
def create_user():
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    username = request.form.get('username')
    if not username:
        return "Username required", 400
    
    token = secrets.token_urlsafe(16)
    color = f"#{secrets.token_hex(3)}"
    
    users[token] = {
        'username': username,
        'user_id': f"user_{uuid.uuid4().hex[:6]}",
        'color': color,
        'created_at': datetime.now().isoformat(),
        'registered': False  # Not registered yet
    }
    
    return redirect(url_for('admin'))

@app.route('/promote_admin/<token>')
def promote_admin(token):
    if not session.get('is_admin'):
        return redirect(url_for('index'))
    
    if token in users:
        admin_tokens[token] = True
        users[token]['is_admin'] = True
    
    return redirect(url_for('admin'))

# Socket.IO events (unchanged)
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_data = {
            'id': session['user_id'],
            'name': session['username'],
            'color': session['color'],
            'is_admin': session.get('is_admin', False)
        }
        emit('user_connected', user_data)
        
        # Join workspace room
        workspace_id = session.get('workspace_id', 'default_workspace')
        join_room(workspace_id)
        
        # Add user to workspace
        if workspace_id in workspaces:
            workspaces[workspace_id]['users'][session['user_id']] = user_data
            emit('workspace_users', workspaces[workspace_id]['users'], room=workspace_id)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        workspace_id = session.get('workspace_id', 'default_workspace')
        leave_room(workspace_id)
        
        # Remove user from workspace
        if workspace_id in workspaces and session['user_id'] in workspaces[workspace_id]['users']:
            del workspaces[workspace_id]['users'][session['user_id']]
            emit('user_disconnected', {'id': session['user_id']}, room=workspace_id)

@socketio.on('code_change')
def handle_code_change(data):
    workspace_id = session.get('workspace_id', 'default_workspace')
    if workspace_id in workspaces:
        workspaces[workspace_id]['code'] = data['code']
        emit('code_update', {
            'code': data['code'],
            'user_id': session['user_id'],
            'cursor': data.get('cursor', {'line': 0, 'ch': 0})
        }, room=workspace_id, include_self=False)

@socketio.on('cursor_move')
def handle_cursor_move(data):
    workspace_id = session.get('workspace_id', 'default_workspace')
    emit('cursor_update', {
        'user_id': session['user_id'],
        'cursor': data['cursor']
    }, room=workspace_id, include_self=False)

@socketio.on('chat_message')
def handle_chat_message(data):
    workspace_id = session.get('workspace_id', 'default_workspace')
    message = {
        'id': str(uuid.uuid4()),
        'user_id': session['user_id'],
        'username': session['username'],
        'color': session['color'],
        'text': data['message'],
        'timestamp': datetime.now().isoformat()
    }
    
    if workspace_id in workspaces:
        workspaces[workspace_id]['chat'].append(message)
        emit('new_message', message, room=workspace_id)

@socketio.on('execute_code')
def handle_execute_code(data):
    code = data['code']
    
    try:
        # Create a temporary file to execute the code
        with open('temp_code.py', 'w') as f:
            f.write(code)
        
        # Execute the code with timeout
        result = subprocess.run(
            [sys.executable, 'temp_code.py'],
            capture_output=True,
            text=True,
            timeout=10  # 10 seconds timeout
        )
        
        output = result.stdout
        errors = result.stderr
        
        # Clean up
        os.remove('temp_code.py')
        
        emit('execution_result', {
            'output': output,
            'errors': errors,
            'status': 'success' if not errors else 'error'
        })
        
    except subprocess.TimeoutExpired:
        emit('execution_result', {
            'output': '',
            'errors': 'Execution timed out (10 seconds limit)',
            'status': 'timeout'
        })
    except Exception as e:
        emit('execution_result', {
            'output': '',
            'errors': str(e),
            'status': 'error'
        })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
