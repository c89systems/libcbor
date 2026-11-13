"""Bounded data fixture: Python-CWT does COSE, CTest owns all assertions.

The X25519 fixture uses independent cryptography primitives because Python-CWT
4.0.0 hard-codes EC2 in ECDH-ES key-wrap. It is deliberately identified separately
from library interoperability, with no protected-header rewriting or aliases.
Keys below are public test vectors, never application defaults.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import traceback
import cbor2
from cwt import COSE, COSEKey, Recipient
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RAW = bytes(31) + b'\x01'
AAD = b'libcbor-e2e'
COSE_ENGINE = COSE.new()

def key(family):
    if family in ('gcm', 'kw', 'hmac'):
        return COSEKey.from_symmetric_key(RAW, alg={'gcm': 3, 'kw': -5, 'hmac': 5}[family])
    private = (ed25519.Ed25519PrivateKey.from_private_bytes(RAW) if family == 'ed'
               else ec.derive_private_key(1, ec.SECP256R1()))
    pem = private.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    return COSEKey.from_pem(pem, alg=-19 if family == 'ed' else -9)

def x_fixture(data, sealing, aad):
    recipient = x25519.X25519PrivateKey.from_private_bytes(RAW)
    if sealing:
        ephemeral = x25519.X25519PrivateKey.generate()
        header = cbor2.dumps({1: -31})
        nonce, cek = os.urandom(12), os.urandom(32)
        public = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(recipient.public_key())
    else:
        value = cbor2.loads(data)
        if value.tag != 96:
            raise ValueError('expected Encrypt')
        body, unprotected, ciphertext, recipients = value.value
        header, u, wrapped = recipients[0]
        if cbor2.loads(body) != {1: 3} or (cbor2.loads(header).get(1) if header else u.get(1)) != -31:
            raise ValueError('unexpected algorithm')
        public = u[-1][-2]
        nonce = unprotected[5]
        shared = recipient.exchange(x25519.X25519PublicKey.from_public_bytes(public))
    context = [-5, [None, None, None], [None, None, None], [256, header]]
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=cbor2.dumps(context)).derive(shared)
    if sealing:
        body = cbor2.dumps({1: 3})
        ciphertext = AESGCM(cek).encrypt(nonce, data, cbor2.dumps(['Encrypt', body, aad]))
        return cbor2.dumps(cbor2.CBORTag(96, [body, {5: nonce}, ciphertext,
            [[header, {-1: {1: 1, -1: 4, -2: public}}, aes_key_wrap(kek, cek)]]]))
    cek = aes_key_unwrap(kek, wrapped)
    return AESGCM(cek).decrypt(nonce, ciphertext, cbor2.dumps(['Encrypt', body, aad]))

def transform(family, data, sealing, aad):
    if family.startswith('cwt-'):
        _, auth, encryption = family.split('-')
        if sealing:
            inner = transform(auth, data, True, aad)
            return cbor2.dumps(cbor2.CBORTag(61, cbor2.loads(transform(encryption, inner, True, aad))))
        value = cbor2.loads(data)
        if value.tag != 61:
            raise ValueError('expected CWT tag')
        inner = transform(encryption, cbor2.dumps(value.value), False, aad)
        return transform(auth, inner, False, aad)
    if family == 'x':
        return x_fixture(data, sealing, aad)
    k = key(family)
    if not sealing:
        return COSE_ENGINE.decode(data, k, external_aad=aad)
    if family == 'kw':
        recipient = Recipient.new(unprotected={1: -5}, sender_key=k)
        return COSE_ENGINE.encode_and_encrypt(data, key=COSEKey.from_symmetric_key(os.urandom(32), alg=3),
            protected={1: 3}, recipients=[recipient], external_aad=aad)
    if family == 'gcm':
        return COSE_ENGINE.encode_and_encrypt(data, key=k, protected={1: 3}, external_aad=aad)
    if family == 'hmac':
        return COSE_ENGINE.encode_and_mac(data, key=k, protected={1: 5}, external_aad=aad)
    return COSE_ENGINE.encode_and_sign(data, key=k, protected={1: -19 if family == 'ed' else -9}, external_aad=aad)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404); return
        self.send_response(200); self.end_headers(); self.wfile.write(b'python-cwt/4.0.0')
    def do_POST(self):
        try:
            action, family = self.path.strip('/').split('/')
            if action not in ('seal', 'open'):
                raise ValueError('unknown action')
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= 16384:
                raise ValueError('fixture input bound')
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError('short input')
            aad = bytes.fromhex(self.headers.get('X-AAD', AAD.hex()))
            result = transform(family, data, action == 'seal', aad)
            if len(result) > 16384:
                raise ValueError('fixture output bound')
            self.send_response(200)
            self.send_header('Content-Length', str(len(result)))
            self.end_headers(); self.wfile.write(result)
        except Exception:
            traceback.print_exc()
            self.send_error(422, 'fixture rejected input')

with open('/state/container-write', 'w', encoding='ascii') as marker:
    marker.write('python-cwt/4.0.0\n')
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
