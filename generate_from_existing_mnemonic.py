from key_tools import mnemonic_to_output

mnemonic_phrase = input("enter mnemonic:")
if len(mnemonic_phrase.split(' '))!=24:
    raise ValueError("invalid mnemonic")

with open("./wordlist.txt", "r", encoding="utf-8") as f:
    wordlist = [w.strip() for w in f.readlines()]
    assert len(wordlist)==2048

for word in mnemonic_phrase.split(' '):
    if word not in wordlist:
        raise ValueError(f"invalid word {word}")

mnemonic_to_output(mnemonic_phrase)