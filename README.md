# Minimal Python Bitcoin Wallet Generator

Cryptographic entropy generated by dice rolls or by your machines OS. Both methods generate segwit addresses, use `--p2pkh` flag to generate P2PKH addresses.

- Dice roll method uses 99 rolls and [coldcard scheme](https://coldcard.com/docs/verifying-dice-roll-math/) for 256-bit security.
- Machine OS method uses [mnemonic](https://pypi.org/project/mnemonic/) library (from Trezor) which calls the [secrets](https://docs.python.org/3/library/secrets.html) library to generate entropy, also gives 256-bit security.

Includes functionality to generate a new mnemonic and associated keys, or to reproduce keys from an existing mnemonic.

To run:
```
pip install -r requirements.txt
python generate_from_dice.py
```


#### Disclaimer
This wallet generator is for educational and testing purposes only. For storage of significant funds, an open-source hardware wallet that has been extensively vetted by the bitcoin community is recommended.
