## YouChoose
We explore the issue of anonymously proving account ownership (anonymous PAO) to let a prover prove to a verifier that it owns a valid account at a server without being tracked by the server or the verifier, without requiring any changes at the server's end and without even revealing to it that any anonymous PAO is taking place. This concept has applications in sensitive areas like whistleblowing. The first introduction of anonymous PAOs was by Wang et al., who also introduced the secure channel injection (SCI) protocol to realize anonymous PAO in the context of email account ownership.

In this paper, we propose YouChoose, an approach that improves upon Wang et al.'s SCI-based anonymous PAO. Unlike SCI, which demands carefully designed multi-party computation (MPC) protocols for efficiency, YouChoose works without MPC, simply relying on the verifier to selectively forward TLS records. It is faster, more efficient, and adaptable, with only a few milliseconds overhead compared to SCI's 8 seconds on top of a proxied email transaction carrying a typical email attachment such as an image file. Further, the simplicity of the YouChoose approach readily enables anonymous PAO in different settings such as various ciphersuites of TLS, account types other than email, etc., while the SCI approach needs specifically designed MPC protocols for each use case. The paper also formalizes both YouChoose and SCI into definitions for a generalized anonymous PAO. 

### Prerequisites
* We test this code on Python 3.10.11.
* Install the requirements for tlslite-ng using pip:
```bash
pip install -r requirements.txt
```


## Usage
* To see how tlslite works see [tlslite documentation](./tlslite-notes.md)
* Create new json files with input as per the specifications in the *.template.json files
* Run the prover on one terminal and the verifier on another terminal using the following commands:
```bash
python prover.py
python verifier.py
```
* The server runs as a hosted service such as Gmail, Outlook or [Mailtrap](https://mailtrap.io/)

* The baseline implementation of a standard email transaction proxied through a passive verifier is also provided in the subdirector `baseline`. Run the baseline similar to the above commands.
