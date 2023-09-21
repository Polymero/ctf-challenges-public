#!/usr/local/bin/python
#
# Polymero
#
# CyberHub CTF 2023
#

# Native imports
import os, json, base64

# Non-native imports
from flask import *                          # pip install Flask
from Crypto.Cipher import AES                # pip install pycryptodome
from Crypto.Util.Padding import pad, unpad  

# Local imports
with open('flag.txt', 'rb') as f:
    FLAG = f.read().decode()
    f.close()


# Functions
def GenerateToken(key, username, admin=False):
    plain = json.dumps({
        'username' : username,
        'admin'    : admin
    }).encode()
    userKey = os.urandom(16)
    blindIV = bytes([i ^ j for i,j in zip(key, userKey)])
    cryptor = AES.new(key, AES.MODE_CBC, blindIV)
    token = userKey + cryptor.encrypt(pad(plain, 16))
    return base64.urlsafe_b64encode(token).strip(b'=').decode()

def CheckToken(key, token):
    token = base64.urlsafe_b64decode(token + '===')
    userKey = token[:16]
    blindIV = bytes([i ^ j for i,j in zip(key, userKey)])
    cryptor = AES.new(key, AES.MODE_CBC, blindIV)
    try:
        plain = unpad(cryptor.decrypt(token[16:]), 16)
        return True, json.loads(plain)
    except Exception as e:
        return False, e


# Webpage setup
app = Flask(__name__)
app.secret_key = os.urandom(16)


# Homepage
@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('token')
    if token:
        try:
            t, ret = CheckToken(app.secret_key, token)
            if t:
                usr = ret['username']
                prv = ret['admin']
                flash('Succesfully loaded your token.', 'success')
                if prv:
                    return render_template('index.html', username=' '+usr, content=FLAG)
                else:
                    return render_template('index.html', username=' '+usr, content='You seem to be lacking admin rights...')
            else:
                raise ret
        except Exception as e:
            flash('ERROR: {}'.format(str(e)), 'error')
    else:
        flash('No token found. Get a token by visiting "./gettoken/<username>".', 'warning')
    return render_template('index.html', username='', content='Please load your token or generate a new one.')


# Get token
@app.route('/gettoken/<username>')
def gettoken(username):
    resp = make_response(redirect('/'))
    resp.set_cookie('token', GenerateToken(app.secret_key, username))
    return resp


# Main
if __name__ == '__main__':
    app.run(host='0.0.0.0')
