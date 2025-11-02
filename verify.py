from web3 import Web3
from eth_account.messages import encode_defunct
import random


def sign_challenge(challenge):
    w3 = Web3()


    sk = "0x2636feb609bc58bafc604deb0256ac7c607607e93179b15efbd5f431576a096b"

    acct = w3.eth.account.from_key(sk)
    signed_message = w3.eth.account.sign_message(challenge, private_key=acct.key)
    return acct.address, signed_message.signature


def verify_sig():

    challenge_bytes = random.randbytes(32)
    challenge = encode_defunct(challenge_bytes)
    address, sig = sign_challenge(challenge)
    w3 = Web3()
    recovered = w3.eth.account.recover_message(challenge, signature=sig)
    return recovered == address


if __name__ == "__main__":
    if verify_sig():
        print("You passed the challenge!")
    else:
        print("You failed the challenge!")
