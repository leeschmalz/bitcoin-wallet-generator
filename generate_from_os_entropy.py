from mnemonic import Mnemonic
from datetime import datetime
from key_tools import *

mnemo = Mnemonic("english")
mnemonic_phrase = mnemo.generate(strength=256) # uses secrets.token_bytes to seed

print('\n')
print(mnemonic_phrase)
print('\n')
addresses = []
for ind in range(20):
    privkey, wif, pubkey, addr = generate_keys_from_mnemonic(mnemonic_phrase, ind)
    addresses.append(addr)
    print("Priv:", privkey)
    print("WIF :", wif)
    print("Pub :", pubkey)
    print("Addr:", addr)
    print("\n")

write = input('write public wallet addresses to file?')

current_time = str(datetime.now()).replace('/','-')
filename = f'wallet_addresses_{current_time}.txt'

if write.lower()=='y':
    with open(filename, 'w') as file:
        for address in addresses:
            file.write(address + '\n')
            
    print(f'\naddresses written to: {filename}\n')
    print('WARNING: secrets are not saved. ensure mnemonic is copied before sending funds.\n')