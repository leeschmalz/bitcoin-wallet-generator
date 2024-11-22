import hashlib
from bip32 import BIP32
from mnemonic import Mnemonic
from datetime import datetime
import base58

# Bech32 Encoding Constants
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Compute Bech32 checksum."""
    gen = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
        0x3d4233dd, 0x2a1462b3
    ]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    """Compute the checksum for Bech32."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    """Encode Bech32 address."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    """Convert bits for Bech32 encoding."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or (acc << (tobits - bits)) & maxv:
        return None
    return ret

def privkey_to_wif_compressed(privkey_hex):
    extended_key = "80" + privkey_hex + "01"
    first_sha256 = hashlib.sha256(bytes.fromhex(extended_key)).hexdigest()
    second_sha256 = hashlib.sha256(bytes.fromhex(first_sha256)).hexdigest()
    checksum = second_sha256[:8]
    final_key = extended_key + checksum
    wif_compressed = base58.b58encode(bytes.fromhex(final_key)).decode()
    return wif_compressed

def pubkey_to_p2pkh_address(pubkey_hex):
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

def pubkey_to_segwit_address(pubkey_hex):
    # Generate SHA256 and RIPEMD160 hash of the public key
    pubkey_sha256 = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(pubkey_sha256)
    witprog = ripemd160.digest()

    # Convert to Bech32 address
    data = convertbits(witprog, 8, 5)
    return bech32_encode("bc", [0] + data)  # 'bc' is the mainnet prefix

def generate_keys_from_mnemonic(mnemonic_phrase, ind):
    seed = Mnemonic.to_seed(mnemonic_phrase)
    bip32 = BIP32.from_seed(seed)

    p2pkh_path = f"m/44'/0'/0'/0/{ind}"
    p2pkh_privkey_hex = bip32.get_privkey_from_path(p2pkh_path).hex()
    p2pkh_pubkey_hex = bip32.get_pubkey_from_path(p2pkh_path).hex()

    segwit_path = f"m/84'/0'/0'/0/{ind}"
    segwit_privkey_hex = bip32.get_privkey_from_path(segwit_path).hex()
    segwit_pubkey_hex = bip32.get_pubkey_from_path(segwit_path).hex()

    p2pkh_wif_compressed = privkey_to_wif_compressed(p2pkh_privkey_hex)
    p2pkh_address = pubkey_to_p2pkh_address(p2pkh_pubkey_hex)

    segwit_wif_compressed = privkey_to_wif_compressed(segwit_privkey_hex)
    segwit_address = pubkey_to_segwit_address(segwit_pubkey_hex)

    return p2pkh_wif_compressed, segwit_wif_compressed, segwit_pubkey_hex, p2pkh_pubkey_hex, segwit_address, p2pkh_address

def mnemonic_to_output(mnemonic_phrase, n_keys=20, address_type='segwit'):
    print('\n')
    print(mnemonic_phrase)
    print('\n')
    addresses = []
    for ind in range(n_keys):
        p2pkh_wif_compressed, segwit_wif_compressed, segwit_pubkey_hex, p2pkh_pubkey_hex, segwit_address, p2pkh_address = generate_keys_from_mnemonic(mnemonic_phrase, ind)

        if address_type == 'p2pkh':
            addresses.append(p2pkh_address)
            print("P2PKH WIF:", p2pkh_wif_compressed)
            print("P2PKH Pub: ", p2pkh_pubkey_hex)
            print("P2PKH Addr:", p2pkh_address)
        elif address_type == 'segwit':
            addresses.append(segwit_address)
            print("Segwit WIF :", segwit_wif_compressed)
            print("Segwit Pub :", segwit_pubkey_hex)
            print("Segwit Addr:", segwit_address)
        else:
            exit('unrecognized address type.')
        print("\n")

    write = input('write public wallet addresses to file?')

    current_time = str(datetime.now()).replace('/','-')
    filename = f'wallet_addresses_{current_time}.txt'

    if write.lower() == 'y':
        with open(filename, 'w') as file:
            for address in addresses:
                file.write(address + '\n')
                
        print(f'\naddresses written to: {filename}\n')
        print('WARNING: secrets are not saved. ensure mnemonic is copied before sending funds.\n')
