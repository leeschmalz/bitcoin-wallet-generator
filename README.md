# Minimal Python Bitcoin Wallet Generator

Cryptographic entropy generated by [mnemonic](https://pypi.org/project/mnemonic/) library (from Trezor). Generates legacy P2PKH addresses using BIP39 (no multi-sig, SegWit, etc.).

Includes functionality to generate a new mnemonic and associated keys, or reproduce keys from existing mnemonic.

To run:
```
pip install -r requirements.txt
python generate.py
```


#### Disclaimer
This wallet generator is for educational and testing purposes only. For the storage of significant funds, it is recommended to use an open-source hardware wallet that has been extensively vetted by the bitcoin community.
