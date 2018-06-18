from __future__ import print_function
from bs4 import BeautifulSoup
from flask import Flask, request
from asn1crypto.x509 import Certificate
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import os, sys, sqlite3, requests, json, binascii

app = Flask(__name__)
db_name = 'logit.db'
dbcon = None

def init_db(dbcon):
    dbcon.execute("CREATE TABLE Users (id INTEGER PRIMARY KEY autoincrement NOT NULL, uid TEXT, user TEXT, name TEXT, surname TEXT, cert TEXT, time TIMESTAMP DEFAULT current_timestamp NOT NULL)")
    dbcon.execute("CREATE TABLE Attendances (id INTEGER PRIMARY KEY autoincrement NOT NULL, sid TEXT, mid TEXT, uid TEXT, lat TEXT, lon TEXT, ts TEXT, sig TEXT, aid TEXT, confsig TEXT, cid TEXT, time TIMESTAMP DEFAULT current_timestamp NOT NULL)")
    dbcon.execute("CREATE TABLE Sessions (id INTEGER PRIMARY KEY autoincrement NOT NULL, sid TEXT, sig TEXT, master TEXT, time TIMESTAMP DEFAULT current_timestamp NOT NULL)")
    dbcon.commit()

if not os.path.isfile(db_name):
    dbcon = sqlite3.connect(db_name)
    init_db(dbcon)
else:
    dbcon = sqlite3.connect(db_name)

@app.route("/")
def main():
    return 'Work'

@app.route("/auth/", methods=['POST'])
def auth():
    user = request.form['user']
    passw = request.form['pass']
    cert = request.form['cert']
    uid = request.form['uid']
    s = requests.Session()
    r = s.post('https://zamger.etf.unsa.ba/index.php', data={'loginforma':1, 'login': user, 'pass': passw})
    r = s.get('https://zamger.etf.unsa.ba/index.php?sta=common/profil')
    soup = BeautifulSoup(r.text, 'html.parser')
    nameTag = soup.find('input', attrs={"name": "ime"})
    surnameTag = soup.find('input', attrs={"name": "prezime"})
    name = nameTag['value'].encode('utf8')
    surname = surnameTag['value'].encode('utf8')
    dbcon.execute("INSERT INTO Users (uid, user, name, surname, cert) VALUES (?, ?, ?, ?, ?)", (uid, user, buffer(name), buffer(surname), cert))
    dbcon.commit()
    return json.dumps({ 'name': name, 'surname': surname})

@app.route("/validate/", methods=['POST'])
def validate():
    data = request.data
    attns = json.loads(data)
    # print(attns, file=sys.stderr)
    c = dbcon.cursor()

    result = []

    for attn_string in attns:
        attn = json.loads(attn_string)
        c.execute("SELECT max(id) id FROM Users WHERE user=? GROUP BY user", (attn['user'],))
        certId = c.fetchone()
        c.execute("SELECT * FROM Users WHERE id = ?", (certId[0],))
        user = c.fetchone()
        cert = Certificate.load(binascii.unhexlify(user[5]))
        n = cert.public_key.native['public_key']['modulus']
        e = cert.public_key.native['public_key']['public_exponent']
        package = attn['user'] + ':' + attn['lat'] + ':' + attn['lon'] + ':' + attn['ts']
        digest = SHA256.new()
        digest.update(package)

        public_key = RSA.construct((n, e))

        verifier = PKCS1_v1_5.new(public_key)
        verified = verifier.verify(digest, binascii.unhexlify(attn['sig']))

        attn['valid'] = 1 if verified else -1
        attn['raw'] = json.dumps(attn)
        attn['name'] = binascii.unhexlify(attn['name'])
        attn['surname'] = binascii.unhexlify(attn['surname'])
        result.append(attn)
        # print(verified, file=sys.stderr)

    return json.dumps(result)

@app.route("/sync/", methods=['POST'])
def sync():
    data = request.data
    session = json.loads(data)
    c = dbcon.cursor()
    c.execute("SELECT * FROM Users WHERE uid = ?", (session['mid'],))
    master = c.fetchone()
    cert = Certificate.load(binascii.unhexlify(master[5]))
    n = cert.public_key.native['public_key']['modulus']
    e = cert.public_key.native['public_key']['public_exponent']

    hash_package = ''.join(sorted([attn['cid'] for attn in session['attns']]))
    digest = SHA256.new()
    digest.update(hash_package)

    public_key = RSA.construct((n, e))

    verifier = PKCS1_v1_5.new(public_key)
    verified = verifier.verify(digest, binascii.unhexlify(session['sig']))

    if verified:
        dbcon.execute("INSERT INTO Sessions (sid, sig, master) VALUES (?, ?, ?)", (session['sid'], session['sig'], session['master']))
        for attn in session['attns']:
            db_tuple = (attn['sig'], attn['mid'], attn['uid'], attn['lat'], attn['lon'], attn['ts'], attn['sig'], attn['aid'], attn['confsig'], attn['cid'])
            dbcon.execute("INSERT INTO Attendances (sid, mid, uid, lat, lon, ts, sig, aid, confsig, cid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", db_tuple)
        dbcon.commit()
        return "", 201 # Created
    else:
        return "", 401 # Unauthorized

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5000)