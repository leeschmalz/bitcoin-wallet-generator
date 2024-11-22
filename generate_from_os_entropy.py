from mnemonic import Mnemonic
from key_tools import mnemonic_to_output
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--p2pkh", action="store_true")
args = parser.parse_args()
address_type = 'p2pkh' if args.p2pkh else 'segwit'

mnemo = Mnemonic("english")
mnemonic_phrase = mnemo.generate(strength=256)  # uses secrets.token_bytes to seed

mnemonic_to_output(mnemonic_phrase, address_type=address_type)