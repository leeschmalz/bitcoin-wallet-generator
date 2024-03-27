from mnemonic import Mnemonic
from key_tools import mnemonic_to_output

mnemo = Mnemonic("english")
mnemonic_phrase = mnemo.generate(strength=256) # uses secrets.token_bytes to seed

mnemonic_to_output(mnemonic_phrase)