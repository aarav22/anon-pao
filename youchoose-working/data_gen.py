import otc
import base64
import pickle



r_publics = []
r_secrets = []

for i in range(0, 82):
    r = otc.receive()
    r_publics.append(r.public)
    r_secrets.append(r.secret)

with open('keys/r_publics.pem', 'wb') as f:
    pickle.dump(r_publics, f)

with open('keys/r_secrets.pem', 'wb') as f:
    pickle.dump(r_secrets, f)

r = otc.receive()
s = otc.send()


# save each s and r public and secret to 4 files:

# with open('keys/s_public.pem', 'wb') as f:
#     f.write(pickle.dumps(s.public))

# with open('keys/s_secret.pem', 'wb') as f:
#     f.write(pickle.dumps(s.secret))

# with open('keys/r_public.pem', 'wb') as f:
#     f.write(pickle.dumps(r.public))

# with open('keys/r_secret.pem', 'wb') as f:
#     f.write(pickle.dumps(r.secret))

# load keys from files:
with open('keys/s_public.pem', 'rb') as f:
    s.public = pickle.load(f)

with open('keys/s_secret.pem', 'rb') as f:
    s.secret = pickle.load(f)


with open('keys/r_publics.pem', 'rb') as f:
    r_publics = pickle.load(f)

with open('keys/r_secrets.pem', 'rb') as f:
    r_secrets = pickle.load(f)


# with open('keys/r_public.pem', 'rb') as f:
#     r.public = pickle.load(f)

# with open('keys/r_secret.pem', 'rb') as f:
#     r.secret = pickle.load(f)

selections = []
for i in range(0, 81):
    r.public = r_publics[i]
    r.secret = r_secrets[i]
    selections.append(r.query(s.public, 0))

with open("keys/selections.pem", 'wb') as f:
    pickle.dump(selections, f)

with open("keys/selections.pem", 'rb') as f:
    selections = pickle.load(f)


replies = s.reply(selections[80], bytes([0] * 16384), bytes([255] * 16384))
r.elect(s.public, 0, *replies) == bytes([0] * 16384)

