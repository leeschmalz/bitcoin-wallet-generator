from mnemonic import Mnemonic
from bip32 import BIP32
import hashlib
import base58
from datetime import datetime

def privkey_to_wif_compressed(privkey_hex):
    extended_key = "80" + privkey_hex + "01"
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_key)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    final_key = extended_key + checksum
    wif_compressed = base58.b58encode(bytes.fromhex(final_key)).decode()

    return wif_compressed

def pubkey_to_address(pubkey_hex):
    pubkey_sha256 = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    h = hashlib.new('ripemd160')
    h.update(pubkey_sha256)
    pubkey_ripemd160 = h.digest().hex()
    extended_ripemd160 = "00" + pubkey_ripemd160
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_ripemd160)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    final_address = extended_ripemd160 + checksum
    address = base58.b58encode(bytes.fromhex(final_address)).decode()

    return address

def generate_keys(mnemonic_phrase, ind):
    seed = Mnemonic.to_seed(mnemonic_phrase)
    bip32 = BIP32.from_seed(seed)
    path = f"m/44'/0'/0'/0/{ind}"
    privkey_hex = bip32.get_privkey_from_path(path).hex()
    pubkey_hex = bip32.get_pubkey_from_path(path).hex()

    wif_compressed = privkey_to_wif_compressed(privkey_hex)
    address = pubkey_to_address(pubkey_hex)

    return privkey_hex, wif_compressed, pubkey_hex, address


mnemonic_phrase = input("enter mnemonic (leave blank to generate new):")
if len(mnemonic_phrase.split(' '))!=24 and mnemonic_phrase!='':
    raise ValueError("invalid mnemonic")

if mnemonic_phrase=='':
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=256)

print(mnemonic_phrase)
print('\n')
addresses = []
for ind in range(20):
    privkey, wif, pubkey, addr = generate_keys(mnemonic_phrase, ind)
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