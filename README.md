## YouChoose
YouChoose allows anonymous proof of account ownership (PAO) for email identities. Using a PAO, a prover proves ownership of an email address but in conventional methods the prover ends up revealing their full email address to the verifier. For example, OTP based challenges &ndash; prover enters their email address on the verifier's website and recieves a challenge on that email address from the verifier. To prove ownership, the prover retrieves the challenge and submits it to the verifier.

YouChoose allows the prover to prove ownership of their email address without revealing their full email address to the verifier. It is based on SCI first introduced by Wang et al. in [1]. 


## Installation

### Prerequisites
* Python 3.6 or higher



## Usage
* To see how tlslite works see [tlslite documentation](./tlslite-notes.md)
* Modified installation of otc library is available [here](https://github.com/aarav22/otc)
    * changes were made to remove the 16 bytes restriction and consequently made changes in reply() and elect() methods
* Currently, prover and verifier have a private and public key pair each. They are both stored in files. Additionally, a selection.pkl file is created by the verifier which contains its encrypted selection that the prover uses to generate replies.

## Bibliography
[1] Blind Certificate Authorities: https://eprint.iacr.org/2018/1022