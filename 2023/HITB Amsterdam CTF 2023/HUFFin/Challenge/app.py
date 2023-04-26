#!/usr/local/bin/python
#
# Polymero
#
# HITB CTF 2023
#

# Native imports
import os, json, base64

# Non-native imports
from flask import *             # pip install Flask
from Crypto.Cipher import AES   # pip install pycryptodome

# Local imports
FLAG = os.environ.get('FLAG', 'CTFae{d3bug_fl4g}')
if type(FLAG) == bytes:
    FLAG = FLAG.decode()


# Base64 en- and decoding functions
def b64enc(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip('=')

def b64dec(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + '===')


# Challenge class
class HUFFIN:

    ALP = '{":, }ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    def __init__(self):
        self.KEY = os.urandom(32)
        self.RIV = os.urandom(12)
        self.PWD = {}

    def __compress(self, txt, tld={}):
        if not tld:
            cnt = {}
            for i in txt:
                try:
                    cnt[i] += 1
                except:
                    cnt[i] = 1
            lst = [[cnt[i], i] for i in cnt]
            lst.sort()
            tld = { i : '' for i in cnt }
            while len(lst) > 1:
                tmp = lst[:2]
                for i in list(tmp[0][1]):
                    tld[i] += '0'
                for i in list(tmp[1][1]):
                    tld[i] += '1'
                lst = lst[2:] + [[tmp[0][0] + tmp[1][0], tmp[0][1] + tmp[1][1]]]
                lst.sort()
            for i in tld:
                tld[i] = tld[i][::-1]
        cmp = '1'
        for i in txt:
            cmp += tld[i]
        return int(cmp, 2).to_bytes(-(-len(cmp) // 8), 'big'), tld
    
    def __decompress(self, cmp, tld):
        tld = { tld[i] : i for i in tld }
        bts = list(bin(int.from_bytes(cmp, 'big'))[3:])
        txt = ''
        tmp = ''
        while bts:
            tmp += bts.pop(0)
            if tmp in tld:
                txt += tld[tmp]
                tmp = ''
        assert not tmp
        return txt

    def register(self, username, password):
        self.PWD[username] = password
        token = json.dumps({
            'username' : username,
            'password' : password
        })
        token_cmp, tld = self.__compress(token)
        token_enc = AES.new(self.KEY, AES.MODE_CTR, nonce=self.RIV).encrypt(token_cmp)
        tld_tag = '.'.join(tld[i] if i in tld else '' for i in self.ALP)
        tld_cmp = self.__compress(tld_tag, {'0': '11', '1': '0', '.': '10'})[0]
        return b64enc(token_enc) + '.' + b64enc(tld_cmp)
    
    def login(self, token):
        try:
            tmp, tag = [b64dec(i + '===') for i in token.split('.')]
            tmp = AES.new(self.KEY, AES.MODE_CTR, nonce=self.RIV).decrypt(tmp)
            tld = self.__decompress(tag, {'0': '11', '1': '0', '.':'10'}).split('.')
            tld = { self.ALP[i] : tld[i] for i in range(len(self.ALP)) }
            tmp = self.__decompress(tmp, tld)
            tmp = json.loads(tmp)
        except:
            return True, 'Invalid token.'
        try:
            assert huffin.PWD[tmp['username']] == tmp['password']
            return False, tmp['username']
        except:
            return True, 'Invalid username or password..'


# Webpage setup
app = Flask(__name__)
app.secret_key = os.urandom(32)

# Crypto setup (+ create different static secrets for each team)
huffin = HUFFIN()
adminUsername = b64enc(os.urandom(3))
adminPassword = b64enc(os.urandom(9))
FIRST_TIME = True


# Homepage
@app.route('/', methods=['GET', 'POST'])
def index():
    global FIRST_TIME, adminUsername, adminPassword
    if request.method == 'GET':
        if FIRST_TIME:
            admin_token = huffin.register(adminUsername, adminPassword)
            resp = make_response(redirect('/'))
            resp.set_cookie('token', admin_token)
            FIRST_TIME = False
            return resp
        token = request.cookies.get('token')
        if token is not None:
            err, usr = huffin.login(token)
            if err:
                flash(usr, 'error')
            else:
                # TEMPORARILY DISABLED
                flash('Token logins are temporarily disabled. Please use the manual login.', 'warning')
    if request.method == 'POST':
        usr = request.form['username']
        pwd = request.form['password']
        try:
            assert huffin.PWD[usr] == pwd
            flash('Successfully logged in as ' + usr + '.', 'success')
            if usr == adminUsername:
                return render_template('flag.html', flag=FLAG)
            return render_template('flag.html', flag='Nothing to see here.')
        except:
            flash('Invalid username or password.', 'error')        
    return render_template('index.html')


# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usr = request.form['username']
        pwd_1 = request.form['password_1']
        pwd_2 = request.form['password_2']
        try:
            assert usr and pwd_1 and pwd_2
            assert pwd_1 == pwd_2
            token = huffin.register(usr, pwd_1)
            resp = make_response(redirect('/'))
            resp.set_cookie('token', token)
            flash('Succesfully registered ' + usr + '. Your token has been set.', 'success')
            return resp
        except:
            flash('Something went wrong during registration.', 'error')
    return render_template('register.html')


# Main
if __name__ == '__main__':
    app.run(host='0.0.0.0')