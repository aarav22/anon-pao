## YouChoose
We explore the issue of anonymously proving account ownership (anonymous PAO) to let a prover prove to a verifier that it owns a valid account at a server without being tracked by the server or the verifier, without requiring any changes at the server's end and without even revealing to it that any anonymous PAO is taking place. This concept has applications in sensitive areas like whistleblowing. The first introduction of anonymous PAOs was by Wang et al., who also introduced the secure channel injection (SCI) protocol to realize anonymous PAO in the context of email account ownership.

In this paper, we propose YouChoose, an approach that improves upon Wang et al.'s SCI-based anonymous PAO. Unlike SCI, which demands carefully designed multi-party computation (MPC) protocols for efficiency, YouChoose works without MPC, simply relying on the verifier to selectively forward TLS records. It is faster, more efficient, and adaptable, with only a few milliseconds overhead compared to SCI's 8 seconds on top of a proxied email transaction carrying a typical email attachment such as an image file. Further, the simplicity of the YouChoose approach readily enables anonymous PAO in different settings such as various ciphersuites of TLS, account types other than email, etc., while the SCI approach needs specifically designed MPC protocols for each use case. The paper also formalizes both YouChoose and SCI into definitions for a generalized anonymous PAO. 

### Prerequisites
* We test this code on Python 3.10.11.
* Install the requirements for tlslite-ng using pip:
```bash
pip install -r requirements.txt
```

We use the OTC Library for oblivious transfer. You can find the original code [here](https://github.com/nthparty/otc).
However, we made some changes and use a local copy in this project. We remove the condition that the messages must be of length 16.
The underlying symmetric encryption is done using [bcl library](https://github.com/nthparty/bcl) which uses libsodium and can handle very large messages.


## Usage
* Run the prover on one terminal and the verifier on another terminal using the following commands:
```bash
python smtp-server.py
```

```bash
python proxy.py -l 0.0.0.0:5000  -r 127.0.0.1:1025  -m AEAD
```
-l: listen address
-r: remote address
-m: mode

```bash
python client.py -e aead  -c 160
```
-e: encryption mode
-c: number of challenges


* The server runs as a hosted service such as Gmail, Outlook or [Mailtrap](https://mailtrap.io/)

## TLS Implementation Changes

YouChoose extends the tlslite-ng library with the following key modifications:

### Core Components Added

1. **YouChooseRecordLayerExtension** (`tlslite/recordlayer.py`)
   - Implements selective TLS record dropping using oblivious transfer (for AEAD mode)
   - Pairs consecutive records with identical sequence numbers (for CBC mode)

2. **YouChooseMessageProcessingExtension** (`tlslite/tlsrecordlayer.py`)  
   - Handles high-level message processing and protocol coordination
   - Manages dynamic record size limits for performance

3. **Performance Optimizations** (`tlslite/utils/aesgcm.py`)
   - Integrates cryptography library for faster AEAD operations
   - Replaces pure-Python implementations with optimized C code

