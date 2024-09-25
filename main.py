from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE
import imaplib
import email
from email.header import decode_header

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'random_secret_key'

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model for database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# LDAP and IMAP server details
ldap_server = 'ldap://your_iredmail_ldap_server'
ldap_user = 'cn=Manager,dc=example,dc=com'  # LDAP bind DN
ldap_password = 'your_password'

imap_server = 'imap.yourdomain.com'  # IMAP server for email
imap_user = 'your_email@example.com'
imap_password = 'your_password'

# Function to fetch users from LDAP
def get_ldap_users():
    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, ldap_user, ldap_password, auto_bind=True)

    # Search users
    users_search_base = 'ou=Users,domainName=example.com,o=domains,dc=example,dc=com'
    users_search_filter = '(objectClass=mailUser)'
    conn.search(users_search_base, users_search_filter, search_scope=SUBTREE, attributes=['mail', 'uid', 'cn'])
    users = [{'mail': str(entry.mail), 'uid': str(entry.uid), 'cn': str(entry.cn)} for entry in conn.entries]

    # Search domains
    domains_search_base = 'o=domains,dc=example,dc=com'
    domains_search_filter = '(objectClass=domainRelatedObject)'
    conn.search(domains_search_base, domains_search_filter, search_scope=SUBTREE, attributes=['associatedDomain'])
    domains = [{'domain': str(entry.associatedDomain)} for entry in conn.entries]

    conn.unbind()
    return {'users': users, 'domains': domains}

# Function to fetch emails from IMAP
def fetch_emails(folder_name):
    mail = imaplib.IMAP4_SSL(imap_server)
    mail.login(imap_user, imap_password)

    # Select the folder (e.g., INBOX, Sent, Spam)
    mail.select(folder_name)
    status, messages = mail.search(None, 'ALL')

    email_list = []
    mail_ids = messages[0].split()

    for mail_id in mail_ids:
        status, msg_data = mail.fetch(mail_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg['Subject'])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else 'utf-8')
                from_ = msg.get('From')
                date = msg.get('Date')
                email_list.append({
                    'Subject': subject,
                    'From': from_,
                    'Date': date
                })

    mail.logout()
    return email_list

# API Endpoint for user registration
@app.route('/api/register', methods=['POST'])
def register():
    try:
        username = request.json['username']
        password = request.json['password']
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# API Endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
    try:
        username = request.json['username']
        password = request.json['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({'message': 'Login successful'}), 200
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# API Endpoint for user logout
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# API Endpoint to get users and domains from LDAP
@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    try:
        data = get_ldap_users()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API Endpoint to get emails from IMAP folders
@app.route('/api/emails', methods=['GET'])
@login_required
def get_emails():
    try:
        inbox_emails = fetch_emails('INBOX')
        sent_emails = fetch_emails('Sent')
        spam_emails = fetch_emails('Spam')

        data = {
            'Inbox': inbox_emails,
            'Sent': sent_emails,
            'Spam': spam_emails
        }

        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
