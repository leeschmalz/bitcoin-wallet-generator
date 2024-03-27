from key_tools import mnemonic_to_output

mnemonic_phrase = input("enter mnemonic:")
if len(mnemonic_phrase.split(' '))!=24:
    raise ValueError("invalid mnemonic")

mnemonic_to_output(mnemonic_phrase)