Assignment 1 - Files encryption

######################################################################################################################################

Usage

    main.py: The main entry point for the project, which provides a command-line interface for executing encryption and decryption commands.

######################################################################################################################################

Dependencies

    To run this project, you need to have the following dependencies installed:

        Python 3
        The Crypto library (you can install it using pip install pycryptodome)
        Or run pip install -r requirements.txt

######################################################################################################################################

How to Run

    To test and use the encryption project, follow these steps:

        Clone or download the project to your local machine.
        Install the required dependencies, especially the Crypto library.
        Use the command-line interface provided by main.py to encrypt and decrypt files using various encryption modes.

######################################################################################################################################

Commands

    The project supports the following commands:

        symmetric: Perform symmetric encryption or decryption.
            --mode: Choose the encryption mode (ecb, cbc, gcm).
            --input: Specify the input file to be encrypted or decrypted.
            --output: Specify the output file to save the result.
            --operation: Choose the operation (encrypt, decrypt).
            --passphrase: Provide the passphrase for encryption and decryption.

        asymmetric-encryption: Perform asymmetric encryption.
            --public_key: Specify the path to the recipient's public key.
            --input: Specify the input file to be encrypted.
            --output: Specify the path to save the encrypted file.

        asymmetric-decryption: Perform asymmetric decryption.
            --private_key: Specify the path to your private key.
            --input: Specify the input file to be decrypted.
            --output: Specify the path to save the decrypted file.

    To run a command, use the following syntax:

        python3 main.py <command> [options]

        for example:

        python3 main.py symmetric --mode ecb --operation encrypt --input tests/image.jpg --output tests/encrypted_image.jpg --passphrase mysecretpassword

        For more examples, just look at what's inside the Examples.txt inside the tests folder.