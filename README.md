# Anonymous Proof of Account Ownership

This repository contains implementations for anonymous proof of account ownership (PAO) protocols.

## Structure

- **`sci/`**: Implementation of Secure Channel Injection (SCI) protocol - existing work from [Wang et al.](https://eprint.iacr.org/2018/1022.pdf)
- **`youchoose/`**: YouChoose implementation - an improved approach that eliminates the need for MPC protocols

## Overview

Both implementations enable anonymous proof of email account ownership, allowing a prover to demonstrate account control to a verifier without revealing their identity. YouChoose improves upon SCI by using selective TLS record forwarding instead of complex MPC protocols, resulting in significantly better performance and more generality.

