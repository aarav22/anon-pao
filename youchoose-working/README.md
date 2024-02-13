Note: This build uses the new proxy server.

## YouChoose
We explore the issue of anonymously proving account ownership (anonymous PAO) to let a prover prove to a verifier that it owns a valid account at a server without being tracked by the server or the verifier, without requiring any changes at the server's end and without even revealing to it that any anonymous PAO is taking place. This concept has applications in sensitive areas like whistleblowing. The first introduction of anonymous PAOs was by Wang et al., who also introduced the secure channel injection (SCI) protocol to realize anonymous PAO in the context of email account ownership.

In this paper, we propose YouChoose, an approach that improves upon Wang et al.'s SCI-based anonymous PAO. Unlike SCI, which demands carefully designed multi-party computation (MPC) protocols for efficiency, YouChoose works without MPC, simply relying on the verifier to selectively forward TLS records. It is faster, more efficient, and adaptable, with only a few milliseconds overhead compared to SCI's 8 seconds on top of a proxied email transaction carrying a typical email attachment such as an image file. Further, the simplicity of the YouChoose approach readily enables anonymous PAO in different settings such as various ciphersuites of TLS, account types other than email, etc., while the SCI approach needs specifically designed MPC protocols for each use case. The paper also formalizes both YouChoose and SCI into definitions for a generalized anonymous PAO. 


## Usage
* To see how tlslite works see [tlslite documentation](./tlslite-notes.md)
* Run the prover on one terminal and the verifier on another terminal using the following commands:
```bash
python client.py -m standard -e cbc -i sandbox.smtp.mailtrap.io -p 587 -s {sender email} -w {sender pwd} -r {receiver email} -t text -c 161
```
```bash
python proxy.py -l 0.0.0.0:5000  -r sandbox.smtp.mailtrap.io:587 -x NONE -m 1
```
In case local testing is required, the following command can be used to run the local email server:
```bash
python server.py
```

Accordingly replace the sender email, sender password, and receiver email with the appropriate values. The -c flag for the client is used to specify the number of challenges to be used and -m flag for the proxy to alternate between AEAD based (2) or non AEAD based (1) cipher.