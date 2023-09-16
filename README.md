# bwJsonDecryptor

Simple python script for decrypting bitwarden vaults exported as **password protected** json files (not account restricted json files, see https://bitwarden.com/help/encrypted-export/). Supports PBKDF2 and Argon2id. Note that json backups do not contain file attachments and password histories (and maybe also sends).

## Usage
```
python bwJsonDecryptor.py filename.json
```

## Output
After entering the password that was used to export the vault, the script prints the content of the vault to the terminal and creates a text file called ```filename.json.txt``` with the vault content.

## Dependencies
Requires packages ```cryptography``` and optionally ```argon2-cffi```.

## Testing
Tested with the export feature directly from vault.bitwarden.com (Version 2023.8.4).

## Credit
Based on the code by https://github.com/GurpreetKang/BitwardenDecrypt.
