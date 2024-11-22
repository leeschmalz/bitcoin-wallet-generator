import hashlib
from key_tools import mnemonic_to_output
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--p2pkh", action="store_true")
args = parser.parse_args()
address_type = 'p2pkh' if args.p2pkh else 'segwit'

# test should result in 
# example1: "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious"
# example2: "garden uphold level clog sword globe armor issue two cute scorpion improve verb artwork blind tail raw butter combine move produce foil feature wave"
example1 = '522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555'
example2 = '222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555'

# collect dice rolls 11 at a time:
dice_rolls = ''; i = 0
while True:
    rolls = input(f'enter dice rolls {i*11+1} - {(i+1)*11}: ')
    if len(rolls)!=11: print(f'expected 11 rolls, got {len(rolls)}\n'); continue

    dice_rolls = dice_rolls + rolls
    if i==8: break
    i+=1

assert len(dice_rolls)==99; f'expected 99 rolls, got {len(dice_rolls)}'

if len(dice_rolls) != 99: raise ValueError('expected 99 rolls.')
bytes = hashlib.sha256(dice_rolls.encode()).digest()

with open("./wordlist.txt", "r", encoding="utf-8") as f:
    wordlist = [w.strip() for w in f.readlines()]
    assert len(wordlist)==2048

if len(bytes) != 32: raise ValueError("Expected 32 bytes.")
h = hashlib.sha256(bytes).hexdigest()
b = (
    bin(int.from_bytes(bytes, byteorder="big"))[2:].zfill(len(bytes) * 8) # first 23 words
    + bin(int(h, 16))[2:].zfill(256)[: len(bytes) * 8 // 32] # checksum
)

mnemonic_phrase = [ wordlist[int(b[i * 11 : (i + 1) * 11], 2)] for i in  range(len(b) // 11)]
mnemonic_phrase = ' '.join(mnemonic_phrase)

mnemonic_to_output(mnemonic_phrase, address_type=address_type)