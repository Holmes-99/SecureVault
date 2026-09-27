from dataclasses import dataclass

class FormatError(Exception):
    pass


# small helpers

def u8(n):
    return n.to_bytes(1, 'big')

def u32(n):
    return n.to_bytes(4, 'big')

def u64(n):
    return n.to_bytes(8, 'big')

def lv(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if len(data) > 0xFFFF:
        raise FormatError("field too long")
    return len(data).to_bytes(2, 'big') + data

def fixed(data, size, name):
    #make sure fixed-size fields really have their size before we write them
    if len(data) != size:
        raise FormatError(f"{name} must be {size} bytes")
    return data


class Reader:
    #reads fields one after another and refuses to read past the end
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise FormatError("data is truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return int.from_bytes(self.take(4), 'big')

    def u64(self):
        return int.from_bytes(self.take(8), 'big')

    def lv(self):
        return self.take(int.from_bytes(self.take(2), 'big'))

    def text(self):
        try:
            return self.lv().decode('utf-8')
        except UnicodeDecodeError:
            raise FormatError("text field is not valid utf-8")

    def magic(self, expected):
        if self.take(len(expected)) != expected:
            raise FormatError("wrong object type")

    def rest(self):
        return self.take(len(self.data) - self.pos)

    def done(self):
        #extra bytes at the end are an error too
        if self.pos != len(self.data):
            raise FormatError("unexpected extra bytes")


#  document object

DOC_MAGIC = b"SVD1"

@dataclass
class Document:
    doc_id: bytes        #16
    owner: str
    filename: str
    mime: str
    size: int
    timestamp: int
    version: int
    nonce: bytes = b""   #12
    ciphertext: bytes = b""
    tag: bytes = b""     #16

def document_header(doc):
    #everything before the nonce
    return (DOC_MAGIC +
            fixed(doc.doc_id, 16, "doc_id") +
            lv(doc.owner) + lv(doc.filename) + lv(doc.mime) +
            u64(doc.size) + u64(doc.timestamp) + u32(doc.version))

def encode_document(doc):
    return (document_header(doc) +
            fixed(doc.nonce, 12, "nonce") +
            u32(len(doc.ciphertext)) + doc.ciphertext +
            fixed(doc.tag, 16, "tag"))

def decode_document(data):
    r = Reader(data)
    r.magic(DOC_MAGIC)
    doc = Document(doc_id=r.take(16), owner=r.text(), filename=r.text(), mime=r.text(),
                   size=r.u64(), timestamp=r.u64(), version=r.u32())
    doc.nonce = r.take(12)
    doc.ciphertext = r.take(r.u32())
    doc.tag = r.take(16)
    r.done()
    return doc



GRANT_MAGIC = b"SVK1"
SEALED_LEN = 96    

@dataclass
class KeyGrant:
    doc_id: bytes        #16
    version: int
    sender: str
    recipient: str
    ephemeral_pk: bytes #32
    nonce: bytes = b"" #12
    sealed: bytes = b"" #96
    tag: bytes = b"" #16

def grant_header(grant):
    return (GRANT_MAGIC +
            fixed(grant.doc_id, 16, "doc_id") + u32(grant.version) +
            lv(grant.sender) + lv(grant.recipient) +
            fixed(grant.ephemeral_pk, 32, "ephemeral_pk"))

def encode_grant(grant):
    return (grant_header(grant) +
            fixed(grant.nonce, 12, "nonce") +
            fixed(grant.sealed, SEALED_LEN, "sealed") +
            fixed(grant.tag, 16, "tag"))

def decode_grant(data):
    r = Reader(data)
    r.magic(GRANT_MAGIC)
    grant = KeyGrant(doc_id=r.take(16), version=r.u32(), sender=r.text(),
                     recipient=r.text(), ephemeral_pk=r.take(32))
    grant.nonce = r.take(12)
    grant.sealed = r.take(SEALED_LEN)
    grant.tag = r.take(16)
    r.done()
    return grant



STATEMENT_MAGIC = b"SVS1"

def signed_statement(doc_id, version, sender, recipient, metadata_hash, plaintext_hash):
    return (STATEMENT_MAGIC +
            fixed(doc_id, 16, "doc_id") + u32(version) +
            lv(sender) + lv(recipient) +
            fixed(metadata_hash, 32, "metadata_hash") +
            fixed(plaintext_hash, 32, "plaintext_hash"))



KEY_BLOB_LEN = 12 + 64 + 16 

@dataclass
class UserRecord:
    username: str
    salt: bytes          
    auth_key: bytes      
    x25519_pk: bytes     
    ed25519_pk: bytes 
    key_blob: bytes

def encode_user(user):
    return (lv(user.username) +
            fixed(user.salt, 16, "salt") +
            fixed(user.auth_key, 32, "auth_key") +
            fixed(user.x25519_pk, 32, "x25519_pk") +
            fixed(user.ed25519_pk, 32, "ed25519_pk") +
            fixed(user.key_blob, KEY_BLOB_LEN, "key_blob"))

def decode_user(data):
    r = Reader(data)
    user = UserRecord(username=r.text(), salt=r.take(16), auth_key=r.take(32),
                      x25519_pk=r.take(32), ed25519_pk=r.take(32),
                      key_blob=r.take(KEY_BLOB_LEN))
    r.done()
    return user




@dataclass
class Request:
    msg_type: int
    username: str
    timestamp: int
    nonce: bytes #16
    body: bytes
    signature: bytes = b"" #64

def request_signed_part(req):
    return (u8(req.msg_type) + lv(req.username) + u64(req.timestamp) +
            fixed(req.nonce, 16, "nonce") + req.body)

def encode_request(req):
    inner = request_signed_part(req) + fixed(req.signature, 64, "signature")
    return u32(len(inner)) + inner

def decode_request(data):
    r = Reader(data)
    length = r.u32()
    if length != len(data) - 4:
        raise FormatError("length field does not match")
    req = Request(msg_type=r.u8(), username=r.text(), timestamp=r.u64(),
                  nonce=r.take(16), body=b"")
    rest = r.rest()
    if len(rest) < 64:
        raise FormatError("data is truncated")
    req.body, req.signature = rest[:-64], rest[-64:]
    return req
