from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, NTLM
# from ldap3.utils import LDAPSocketOpenError  # Example of a specific exception to catch

import imaplib
import email
from email.header import decode_header
import os
import subprocess
import dns.resolver
from flask_login import login_required
import stat
import cloudflare
import logging
import jwt
import datetime
from flask_cors import CORS

app = Flask(__name__)

CORS(app)
# Secret key for session management
app.secret_key = 'random_secret_key'
SECRET_KEY = app.secret_key

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)


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
ldap_server = 'ldap://127.0.0.1:389'
LDAP_SERVER = ldap_server
ldap_user = 'cn=Manager,dc=example,dc=com'  # LDAP bind 
LDAP_USER_DN = ldap_user
ldap_password = 'uvYtV3CDDSPkWCD9OPm6IGtlfDWG3igE'
LDAP_PASSWORD = ldap_password
BASE_DN = 'dc=example,dc=com'  # Change as per your LDAP structure

imap_server = 'imap.yourdomain.com'  # IMAP server for email
imap_user = 'your_email@example.com'
imap_password = 'your_password'

# Function to fetch users from LDAP
def get_ldap_users():
    server = Server(ldap_server, get_info=ALL)
    print("server")
    conn = Connection(server, ldap_user, ldap_password, auto_bind=True)
    print("conn")
    print(conn)
    # Search users
    users_search_base = 'ou=Users,domainName=example.com,o=domains,dc=example,dc=com'
    users_search_filter = '(objectClass=mailUser)'
    conn.search(users_search_base, users_search_filter, search_scope=SUBTREE, attributes=['mail', 'uid', 'cn'])
    users = [{'mail': str(entry.mail), 'uid': str(entry.uid), 'cn': str(entry.cn)} for entry in conn.entries]
    print(users)
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
    # try:
    #     username = request.json['username']
    #     password = request.json['password']
        
    #     hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    #     new_user = User(username=username, password=hashed_password)
    #     db.session.add(new_user)
    #     db.session.commit()
    #     return jsonify({'message': 'User registered successfully'}), 201
    # except Exception as e:
    #     return jsonify({'error': str(e)}), 400
    try:
        username = request.json['username']
        password = request.json['password']
        
        # Hash the password for local storage (if needed)
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # LDAP registration
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=LDAP_USER_DN, password=LDAP_PASSWORD, auto_bind=True)

        # Create the user's DN and attributes
        user_dn = f'uid={username},{BASE_DN}'
        attributes = {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'cn': username,
            'sn': username,
            'uid': username,
            'userPassword': password  # Store the plain password in LDAP (ensure secure connection)
        }
        print(user_dn)
        # Add user to LDAP
        conn.add(user_dn, attributes=attributes)
        if not conn.result['description'] == 'success':
            return jsonify({'error': conn.result['description']}), 400
        
        # Optionally save to your local database
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201

    except LDAPException as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# API Endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
    try:
        # Extract username and password from request
        username = request.json.get('username')
        password = request.json.get('password')
        
        # Find user in the database
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and if the password matches
        if user and check_password_hash(user.password, password):
            login_user(user)
            
            # Create JWT token
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
            }, SECRET_KEY, algorithm='HS256')

            # Return token to the client
            return jsonify({'message': 'Login successful', 'token': token}), 200
        
        # Invalid credentials
        return jsonify({'message': 'Invalid credentials'}), 401
    
    except Exception as e:
        # Return error message for exceptions
        return jsonify({'error': str(e)}), 400

# API Endpoint for user logout
@app.route('/api/logout', methods=['POST'])
# @login_required
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

# LDAP server and credentials
# ldap_server = 'ldap://your_iredmail_ldap_server'
# ldap_user = 'cn=Manager,dc=example,dc=com'  # LDAP bind DN
# ldap_password = 'your_password'

# DKIM keys directory
dkim_keys_dir = '/etc/opendkim/keys'

# Function to add a domain to iRedMail LDAP
def add_domain_to_ldap(domain):
    try:
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, ldap_user, ldap_password, auto_bind=True)
        
        domain_dn = f'domainName={domain},o=domains,dc=example,dc=com'

        # Check if domain already exists
        if conn.search(domain_dn, '(objectClass=domainRelatedObject)'):
            return {'error': f'Domain {domain} already exists'}

        # Add the domain
        domain_attributes = {
            'objectClass': ['top', 'domainRelatedObject'],
            'associatedDomain': domain
        }

        conn.add(domain_dn, attributes=domain_attributes)
        conn.unbind()

        return {'message': f'Domain {domain} added to LDAP successfully'}
    except Exception as e:
        return {'error': str(e)}

# Function to fetch MX records
# def get_mx_records(domain):
#     try:
#         mx_records = dns.resolver.resolve(domain, 'MX')
#         mx_list = [{'priority': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in mx_records]
#         return mx_list
#     except Exception as e:
#         return {'error': str(e)}

def get_mx_records(domain):
    try:
        logging.debug(f"Querying MX records for domain: {domain}")
        mx_records = dns.resolver.resolve(domain, 'MX')
        # mx_list = [{'priority': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in mx_records]
        mx_list = [{'priority': 10, 'exchange': str("smtp.nesthives.com")} for rdata in mx_records]
        logging.debug(f"MX records found: {mx_list}")
        return mx_list
    except dns.resolver.NoAnswer:
        logging.info(f"No MX records found for domain: {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain does not exist: {domain}")
        return {'error': 'Domain does not exist'}
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return {'error': str(e)}

def create_mx_record(domain, priority, exchange):
    try:
        # Replace these with your DNS provider's API token and zone ID
        api_token = 'your_api_token'
        zone_id = 'your_zone_id'

        # Initialize Cloudflare API client
        cf = cloudflare.CloudFlare(token=api_token)

        # Define the new MX record
        mx_record = {
            'type': 'MX',
            'name': domain,
            'content': exchange,
            'priority': priority,
        }

        # Check existing records
        existing_records = cf.zones.dns_records.get(zone_id)
        for record in existing_records:
            if record['type'] == 'MX' and record['name'] == domain:
                logging.info(f"MX record already exists: {record}")
                return

        # Create the new MX record
        response = cf.zones.dns_records.post(zone_id, data=mx_record)
        logging.info(f"Created MX record: {response}")

    except Exception as e:
        logging.error(f"An error occurred while creating MX record: {str(e)}")


# Function to fetch other DNS records (e.g., A, TXT, CNAME)
def get_dns_records(domain, record_type):
    # try:
    #     dns_records = dns.resolver.resolve(domain, record_type)
    #     record_list = [str(rdata) for rdata in dns_records]
    #     return record_list
    # except Exception as e:
    #     return {'error': str(e)}
    try:
        dns_records = dns.resolver.resolve(domain, record_type)
        record_list = [str(rdata) for rdata in dns_records]
        return record_list
    except dns.resolver.NoAnswer:
        return {'error': f'No {record_type} record found for {domain}'}
    except dns.resolver.NXDOMAIN:
        return {'error': f'Domain {domain} does not exist'}
    except dns.resolver.Timeout:
        return {'error': f'Request timed out while resolving {domain}'}
    except dns.resolver.YXDOMAIN:
        return {'error': f'The domain name {domain} is not valid'}
    except Exception as e:
        return {'error': str(e)}

def generate_dkim_key(domain, selector='default'):
    try:
        # Define the DKIM keys directory path
        domain_dir = os.path.join(dkim_keys_dir, domain)
        # print("hello")
        # print(domain_dir)
        try:
            # Create the directory with elevated permissions
            subprocess.run(['sudo', 'mkdir', '-p', domain_dir], check=True)

            # Set directory permissions (700) with elevated permissions
            subprocess.run(['sudo', 'chmod', '700', domain_dir], check=True)

            print(f"Directory {domain_dir} created successfully with 700 permissions.")
            private_key_path = os.path.join(domain_dir, f'{selector}.private')
            public_key_path = os.path.join(domain_dir, f'{selector}.txt')
            print(public_key_path)
            # Run opendkim-genkey with sudo to generate the keys
            subprocess.run(['sudo', 'opendkim-genkey', '-s', selector, '-d', domain, '-D', domain_dir], check=True)
            # # Generate DKIM key pair using opendkim-genkey
            # subprocess.run([
            #     'opendkim-genkey',
            #     '-s', selector,
            #     '-d', domain,
            #     '-D', domain_dir
            # ], check=True)  # Added check=True to raise an exception on non-zero exit code
            
            # # Read and return the public key
            # with open(public_key_path, 'r') as pub_key_file:
            #     public_key = pub_key_file.read()
            public_key = subprocess.run(['sudo', 'cat', public_key_path], capture_output=True, text=True, check=True)
    
            # Print the public key
            # print(public_key.stdout)
            # print(public_key)
            return public_key

        except subprocess.CalledProcessError as e:
            print(f"Error creating or setting permissions for {domain_dir}: {e}")
        # # Create the directory if it doesn't exist
        # try:
        #     # Create the directory if it doesn't exist
        #     os.makedirs(domain_dir, exist_ok=True)

        #     # Set directory permissions (700)
        #     os.chmod(domain_dir, stat.S_IRWXU)

        #     print(f"Directory {domain_dir} exists or was created successfully with 700 permissions.")

        # except OSError as e:
        #     print(f"Error creating or setting permissions for {domain_dir}: {e}")
        # Verify by getting the permission mode
        # permissions = oct(os.stat(domain_dir).st_mode)[-3:]
        # print(permissions)
        # print(f"Permissions set to 700 for: {domain_dir}")
        
        
    except Exception as e:
        return {'error': str(e)}
    

# Function to format DKIM public key for DNS
# def get_dkim_dns_record(domain, public_key, selector='default'):
#     try:
#         dkim_record = f'{selector}._domainkey.{domain}'
#         dkim_value = public_key.strip().replace("\n", "")
#         return {'record': dkim_record, 'value': dkim_value}
#     except Exception as e:
#         return {'error': str(e)}
def get_dkim_dns_record(domain, public_key, selector='default'):
    try:
        # Remove any leading/trailing spaces/newlines and replace internal newlines with nothing
        dkim_record = f'{selector}._domainkey.{domain}'
        dkim_value = public_key.stdout.strip().replace("\n", "")
        return {'record': dkim_record, 'value': dkim_value}
    except Exception as e:
        return {'error': str(e)}
    

# API Endpoint to add a domain, fetch DNS records, and return DKIM
@app.route('/api/domain', methods=['POST'])
# @login_required
def add_domain():
    try:
        domain = request.json['domain']
        selector = request.json.get('selector', 'default')
        # print(domain)
        # Step 1: Add domain to iRedMail LDAP
        ldap_response = add_domain_to_ldap(domain)
        if 'error' in ldap_response:
            return jsonify(ldap_response), 400
        
        # Step 2: Fetch MX, A, TXT, and CNAME records
        mx_records = get_mx_records(domain)
        # print(mx_records)
        if mx_records is None:
            logging.info("MX records not found, creating a new one.")
            # mx_records = create_mx_record(domain, priority=10, exchange=f'mail.{domain}.')
            mx_records = {
                "exchange": "mail.nesthives.com.",
                "priority": 10
            }
        else:
            logging.info(f"Existing MX records: {mx_records}")
        a_records = get_dns_records(domain, 'A')
        txt_records = get_dns_records(domain, 'TXT')
        cname_records = get_dns_records(domain, 'CNAME')

        # Step 3: Generate DKIM keys and get the DNS record
        public_key = generate_dkim_key(domain, selector)
        # print(public_key)
        # print("hello public")
        # if 'error' in public_key:
        #     return jsonify({'error': public_key}), 400
        print("dkim_1")
        # dkim_dns_record = get_dkim_dns_record(domain, public_key, selector)
        # Example usage
        public_key_path = '/etc/opendkim/keys/mibook.in/default.txt'
        # try:
        # Run the command to get the public key content
        public_key = subprocess.run(['sudo', 'cat', public_key_path], capture_output=True, text=True, check=True)
            
        # Generate DKIM DNS record
        # domain = 'mibook.in'
        dkim_dns_record = get_dkim_dns_record(domain, public_key)
            
        # print(dkim_dns_record)
        # print("dkim")
        # Combine the results and return
        data = {
            'domain': domain,
            'MX': mx_records,
            'A': a_records,
            'TXT': txt_records,
            'CNAME': cname_records,
            'DKIM': dkim_dns_record
        }

        return jsonify({'message': 'Domain added successfully', 'dns_records': data}), 201

    except Exception as e:
        print(str(e))
        return jsonify({'error': str(e)}), 500

# API Endpoint to check the domain based on A Record
@app.route('/api/domain_check', methods=['POST'])
def find_domain():
    try:
        domain = request.json['domain']
        data = get_dns_records(domain, 'A')
        return jsonify({'Domains_Details': data}), 201
    except Exception as e:
        print(str(e))
        return jsonify({'error': str(e)}), 500

# Function to search for users by username or email
def search_users(search_term):
    try:
        # LDAP search base
        search_base = 'ou=Users,domainName=example.com,o=domains,dc=example,dc=com'
        search_filter = f'(|(uid=*{search_term}*)(mail=*{search_term}*))'  # Wildcard search

        # Establish LDAP connection
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, ldap_user, ldap_password, auto_bind=True)

        # Search for users in LDAP
        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes=['mail', 'uid'])
        user_entries = conn.entries

        # Extract user details
        users = [{'uid': str(entry.uid), 'mail': str(entry.mail)} for entry in user_entries]

        conn.unbind()
        return {'users': users}
    except Exception as e:
        return {'error': str(e)}

# API Endpoint to search users by username or email
@app.route('/api/search_users', methods=['POST'])
@login_required  # Ensure the user is authenticated
def search_users_endpoint():
    try:
        search_term = request.json['search_term']  # Get search term from the request

        # Search for users
        users = search_users(search_term)
        
        if 'error' in users:
            return jsonify(users), 400
        
        return jsonify({'users': users}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
