import os
import subprocess
import dns.resolver
from flask import Flask, jsonify, request
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from flask_login import login_required

app = Flask(__name__)

# LDAP server and credentials
ldap_server = 'ldap://your_iredmail_ldap_server'
ldap_user = 'cn=Manager,dc=example,dc=com'  # LDAP bind DN
ldap_password = 'your_password'

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
def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = [{'priority': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in mx_records]
        return mx_list
    except Exception as e:
        return {'error': str(e)}

# Function to fetch other DNS records (e.g., A, TXT, CNAME)
def get_dns_records(domain, record_type):
    try:
        dns_records = dns.resolver.resolve(domain, record_type)
        record_list = [str(rdata) for rdata in dns_records]
        return record_list
    except Exception as e:
        return {'error': str(e)}

# Function to generate DKIM key pair
def generate_dkim_key(domain, selector='default'):
    try:
        domain_dir = os.path.join(dkim_keys_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)

        private_key_path = os.path.join(domain_dir, f'{selector}.private')
        public_key_path = os.path.join(domain_dir, f'{selector}.txt')

        # Generate DKIM key pair using opendkim-genkey
        subprocess.run([
            'opendkim-genkey',
            '-s', selector,
            '-d', domain,
            '-D', domain_dir
        ])

        # Read and return the public key
        with open(public_key_path, 'r') as pub_key_file:
            public_key = pub_key_file.read()
        
        return public_key
    except Exception as e:
        return {'error': str(e)}

# Function to format DKIM public key for DNS
def get_dkim_dns_record(domain, public_key, selector='default'):
    try:
        dkim_record = f'{selector}._domainkey.{domain}'
        dkim_value = public_key.strip().replace("\n", "")
        return {'record': dkim_record, 'value': dkim_value}
    except Exception as e:
        return {'error': str(e)}

# API Endpoint to add a domain, fetch DNS records, and return DKIM
@app.route('/api/domain', methods=['POST'])
@login_required
def add_domain():
    try:
        domain = request.json['domain']
        selector = request.json.get('selector', 'default')

        # Step 1: Add domain to iRedMail LDAP
        ldap_response = add_domain_to_ldap(domain)
        if 'error' in ldap_response:
            return jsonify(ldap_response), 400
        
        # Step 2: Fetch MX, A, TXT, and CNAME records
        mx_records = get_mx_records(domain)
        a_records = get_dns_records(domain, 'A')
        txt_records = get_dns_records(domain, 'TXT')
        cname_records = get_dns_records(domain, 'CNAME')

        # Step 3: Generate DKIM keys and get the DNS record
        public_key = generate_dkim_key(domain, selector)
        if 'error' in public_key:
            return jsonify({'error': public_key}), 400
        dkim_dns_record = get_dkim_dns_record(domain, public_key, selector)

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
        return jsonify({'error': str(e)}), 500

# Run the Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


# Explanation:
# Add Domain to LDAP:

# The add_domain_to_ldap() function adds the domain to the iRedMail LDAP server, creating the required domain entry.
# Fetch MX, A, TXT, CNAME Records:

# The get_mx_records() and get_dns_records() functions fetch MX, A, TXT, and CNAME records for the domain using dns.resolver.
# Generate DKIM Key:

# The generate_dkim_key() function generates a DKIM key pair for the domain using the opendkim-genkey command and stores the key in a specified directory (/etc/opendkim/keys).
# The get_dkim_dns_record() function formats the DKIM public key for DNS records.
# API Endpoint /api/domain:

# This API route adds the domain to LDAP, fetches the DNS records, generates DKIM keys, and returns all this information as a JSON response.

# {
#   "message": "Domain added successfully",
#   "dns_records": {
#     "domain": "example.com",
#     "MX": [
#       {
#         "priority": 10,
#         "exchange": "mail.example.com"
#       }
#     ],
#     "A": ["192.168.1.1"],
#     "TXT": ["v=spf1 include:_spf.google.com ~all"],
#     "CNAME": ["mail.example.com"],
#     "DKIM": {
#       "record": "default._domainkey.example.com",
#       "value": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w..."
#     }
#   }
# }
