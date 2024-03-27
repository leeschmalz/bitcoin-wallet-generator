# Minimal Python Bitcoin Wallet Generator

Cryptographic entropy generated by dice rolls or by your machines OS using [mnemonic](https://pypi.org/project/mnemonic/) library (from Trezor). Both method generate legacy P2PKH addresses using BIP39 (no multi-sig, SegWit, etc.).

Dice roll method uses 99 rolls and [coldcard scheme](https://coldcard.com/docs/verifying-dice-roll-math/) for 256-bit security.

Includes functionality to generate a new mnemonic and associated keys, or reproduce keys from existing mnemonic.

To run:
```
pip install -r requirements.txt
python generate_from_dice.py
```


#### Disclaimer
This wallet generator is for educational and testing purposes only. For storage of significant funds, an open-source hardware wallet that has been extensively vetted by the bitcoin community is recommended.
