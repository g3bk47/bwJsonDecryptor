# Copyright © 2023 Thorsten Zirwes
# All rights reserved.
# Released under the "GNU General Public License v3.0". Please see the LICENSE.
# Script for decrypting password protected json files from exported bitwarden vaults.
# Based on the code by https://github.com/GurpreetKang/BitwardenDecrypt
import json, base64, sys, getpass
try:
    from cryptography.hazmat.backends              import default_backend
    from cryptography.hazmat.primitives            import ciphers, hashes, hmac, kdf, padding
    from cryptography.hazmat.primitives.ciphers    import algorithms, Cipher, modes
    from cryptography.hazmat.primitives.kdf.hkdf   import HKDFExpand
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    print("ERROR: package 'cryptography' required! (pip install cryptography)"); sys.exit(1)

# given the json file content ('data') and the passphrase, return the encryption and mac keys
def get_keys(data, passphrase):
    if not (data["encrypted"] and data["passwordProtected"]):
        print("Input: not encrypted or account protected!"); sys.exit(1)

    salt = data["salt"].encode("utf-8")

    if data["kdfType"] == 0: # use PBKDF2 for derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=data["kdfIterations"], backend=default_backend())
        key = kdf.derive(passphrase)

    elif data["kdfType"] == 1: # use Argon2id for derivation
        try:
            import argon2
        except ModuleNotFoundError:
            print("ERROR: package 'argon2-cffi' required! (pip install argon2-cffi)"); sys.exit(1)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        salt_hash = digest.finalize()

        key = argon2.low_level.hash_secret_raw(
            passphrase, salt=salt_hash, time_cost=data["kdfIterations"],
            memory_cost=data["kdfMemory"]*1024, parallelism=data["kdfParallelism"],
            hash_len=32, type=argon2.low_level.Type.ID)
    else:
        print("ERROR: unknown KDF!"); sys.exit(1)

    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc", backend=default_backend()).derive(key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac", backend=default_backend()).derive(key)
    return enc_key, mac_key

# given the encryption and mac keys, as well as encrypted text ('inp'), return the decrypted text
def decrypt(inp, enc_key, mac_key):
    parse = inp.split("|")
    if len(parse) != 3 or len(parse[0]) < 3 or parse[0][0:2] != "2.":
        print("ERROR: incorrect file format!"); sys.exit(1)

    iv    = base64.b64decode(parse[0][2:], validate=True)
    vault = base64.b64decode(parse[1],     validate=True)
    mac   = base64.b64decode(parse[2],     validate=True)

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    h.update(vault)
    if mac != h.finalize():
        print("ERROR! MAC mismatch!"); sys.exit(1)

    cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend()).decryptor()
    decryptor = cipher.update(vault) + cipher.finalize()
    unpadder  = padding.PKCS7(128).unpadder()
    return (unpadder.update(decryptor) + unpadder.finalize()).decode('utf-8')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("ERROR: first argument must be the json file name!"); sys.exit(1)

    with open(sys.argv[1], 'r', encoding="utf-8") as f:
        data = json.load(f)

    enc_key, mac_key = get_keys(data, getpass.getpass(prompt = "Enter Password: ").encode("utf-8"))
    validation = decrypt(data["encKeyValidation_DO_NOT_EDIT"], enc_key, mac_key)
    print("Info: encKeyValidation_DO_NOT_EDIT:", validation)
    vault = decrypt(data["data"], enc_key, mac_key)
    print(vault)
    if len(sys.argv) >= 3 and sys.argv[2] == "--write":
        with open(sys.argv[1]+".txt","w") as f:
            f.write(vault)
        print("Info: decrypted vault written to", sys.argv[1]+".txt")
