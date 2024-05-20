# bwJsonDecryptor

Simple python script for decrypting bitwarden vaults exported as **password protected** json files (not account restricted json files, see https://bitwarden.com/help/encrypted-export/). Supports PBKDF2 and Argon2id. Note that json backups do not contain file attachments, sends, deleted vault items in the trash and shared items.

## Usage
```
python bwJsonDecryptor.py filename.json
```
If you want to create a text file with the content of your vault, add the argument ```--write```.
```
python bwJsonDecryptor.py filename.json --write
```

## Output
After entering the password that was used to export the vault, the script prints the content of the vault to the terminal and optionally creates a text file called ```filename.json.txt``` with the vault content.

## Dependencies
Requires packages ```cryptography``` and optionally ```argon2-cffi```.

## Testing
Tested with the export feature directly from vault.bitwarden.com (last tested with version 2024.4.0).

## Credit
Based on the code by https://github.com/GurpreetKang/BitwardenDecrypt.
