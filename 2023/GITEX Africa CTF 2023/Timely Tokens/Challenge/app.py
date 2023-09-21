#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, time, json, base64

# Non-native imports
from flask import *               # pip install Flask
from Crypto.Cipher import AES     # pip install pycryptodome
from Crypto.Util import Counter 

# Local imports
FLAG = os.environ.get('FLAG', 'flag{th1s_1s_just_s0m3_d3bug_fl4g}')
if type(FLAG) == bytes:
    FLAG = FLAG.decode()


# Functions
def GenerateToken(key, username, admin=False):
    plain = json.dumps({
        'username' : username,
        'admin'    : admin
    }).encode()
    nonce = os.urandom(12)
    timer = int(time.time())
    count = Counter.new(32, prefix=nonce, initial_value=timer)
    crypt = AES.new(key, AES.MODE_CTR, counter=count)
    token = nonce + timer.to_bytes(4, 'big') + crypt.encrypt(plain)
    return base64.urlsafe_b64encode(token).strip(b'=').decode()

def CheckToken(key, token):
    token = base64.urlsafe_b64decode(token + '===')
    nonce = token[:12]
    timer = int.from_bytes(token[12:16], 'big')
    count = Counter.new(32, prefix=nonce, initial_value=timer)
    crypt = AES.new(key, AES.MODE_CTR, counter=count)
    return timer, json.loads(crypt.decrypt(token[16:]))


# Webpage setup
app = Flask(__name__)
app.secret_key = os.urandom(32)


# Homepage
@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('token')
    if token:
        try:
            timer, info = CheckToken(app.secret_key, token)
            assert set(info.keys()) == {'username', 'admin'}
            flash('Successfully loaded token.', 'success')
            if timer > int(time.time()) + 128:
                if info['admin']:
                    return render_template('index.html', username=' '+info['username'], content=FLAG)
                else:
                    return render_template('index.html', username=' '+info['username'], contents='You seem to be lacking admin rights...')
            else:
                return render_template('index.html', username=' '+info['username'], content='My flag is only for future visitors...')
        except:
            flash('Invalid or broken token.', 'error')
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