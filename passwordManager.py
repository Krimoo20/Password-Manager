from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import argparse




# Define a function for key derivation
def key_derivation(master_key):
    # Open the "KeyFile.txt" file in binary mode to read saved parameters
    with open("KeyFile.txt", "rb") as file:
        saved_parameters = file.read()

    # Use the saved parameters (salt) obtained from the file
    salt = saved_parameters

    # Create a PBKDF2HMAC (Password-Based Key Derivation Function 2) object
    # This object uses SHA256 as the hash algorithm for each iteration
    # It derives a key of 32 bytes (256 bits) length from the master key provided by the user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )

    # Use the "derive" method to perform the key derivation
    key = kdf.derive(master_key)

    return key


# Function for password encryption
def password_encryption(password, master_key):
    # Open the "CipherFile.txt" file in binary mode to read the Initialization Vector (IV)
    with open("CipherFile.txt", "rb") as file:
        IV = file.read()

    # Derive an encryption key using the key_derivation function and the provided master key
    enc_key = key_derivation(master_key.encode("utf-8"))

    # Apply PKCS7 padding to the password
    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode("utf-8")) + padder.finalize()

    # Create an AES-CBC cipher object with the derived key and IV
    encrypted_password_object = Cipher(algorithms.AES(enc_key), modes.CBC(IV), backend=default_backend())

    # Create an encryptor object
    encryptor = encrypted_password_object.encryptor()

    # Encrypt the padded password
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    return encrypted_password


# Function for password decryption
def password_decryption(encrypted_password, master_key):
    # Derive a decryption key using the key_derivation function and the provided master key
    key_dec = key_derivation(master_key)

    # Open the "CipherFile.txt" file in binary mode to read the Initialization Vector (IV)
    with open("CipherFile.txt", "rb") as file:
        IV = file.read()

    # Create an AES-CBC cipher object with the derived decryption key and IV
    cipher = Cipher(algorithms.AES(key_dec), modes.CBC(IV), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(encrypted_password) + decryptor.finalize()

    # Unpad the decrypted data using PKCS7 unpadding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(padded_data) + unpadder.finalize()

    # Decode the unpadded data to obtain the plaintext password
    plaintext_password = unpadded_data.decode("utf-8")

    return plaintext_password

# This function would inialize the password manager by creating and generating the necessary files and vaiables
def insialization(user):
    # the lenght of the salt
    n = 64
    # generate a random salt of 64 bits
    salt = b'' + os.urandom(n)

    # Generate an initial vector of 16 byte (128 bits)
    iv = os.urandom(16)
    # Save the salt value
    with open("KeyFile.txt", "wb") as file:
        file.write(salt)

    # Save the initial Vector value used during the encryption process
    with open("CipherFile.txt", "wb") as file:
        file.write(iv)

    # initialization and creation of the database (json file)
    user_data = {
        user: []
    }
    with open("db.json", "w") as created:
        json.dump(user_data, created, indent=2)

# Function to add a new account
def add_new_account(user_name, service):
    user = input("Enter your user name: ")
    master_key = input("Enter your master key: ")
    # Generate a random password using os.urandom and convert it to a string
    password = str(os.urandom(64))
    # Encrypt the random password using the password_encryption function
    encrypted_password = password_encryption(password, master_key)
    # Update the storage with the user details and encrypted password
    update(user, user_name, service, encrypted_password)


# Function to retrieve a password for a given username and service
def retrieve_password(service):
    username=input("Enter your user name: ")
    master_key =input("Enter your master key: ")
    # Open the "db.json" file in read mode to fetch data
    with open("db.json", "r") as file:
        fetched_data = json.load(file)

    # Retrieve the list of accounts associated with the provided username
    account_list = fetched_data[username]

    # Iterate through the accounts to find the one matching the provided service
    for account in account_list:
        if account["Service"] == service:
            # Retrieve the encrypted password from the account
            encrypted_password = account["Password"]

            # Convert the encrypted password to bytes using Latin-1 encoding
            encrypted_password = encrypted_password.encode('latin-1')

            # Decrypt and print the password using the password_decryption function
            password_decryption(encrypted_password, master_key.encode("utf-8"))

            # Break out of the loop since the password has been retrieved
            break


# Function to update the password for a given username, service, and option
def update_password(service):
    username=input("Enter your user name: ")
    master_key=input("Enter your master key: ")
    index = 0
    # Open the "db.json" file in read mode to fetch data
    with open("db.json", "r") as fitch:
        fetched_data = json.load(fitch)

    # Retrieve the list of accounts associated with the provided username
    account_list = fetched_data[username]

    # Iterate through the accounts to find the one matching the provided service
    for account in account_list:
        if account["Service"] == service:

            # User wants to generate a random password
            new_password = str(os.urandom(64))

            # Encrypt the new password using the password_encryption function
            encrypted_password = password_encryption(new_password, master_key)

            # Update the account's password in the data
            account["Password"] = encrypted_password.decode('latin-1')

            # Update the data for the username with the modified account list
            fetched_data[username] = account_list

            # Write the updated data back to the "db.json" file
            with open("db.json", "w") as load:
                json.dump(fetched_data, load, indent=2)

            break

        index += 1


# Function to delete an account for a given username and service
def delete_account(username, service_to_delete):
    index = 0

    # Open the "db.json" file in read mode to fetch data
    with open("db.json", "r") as fitch:
        fetched_data = json.load(fitch)

    # Retrieve the list of accounts associated with the provided username
    account_list = fetched_data[username]

    # Iterate through the accounts to find the one matching the provided service
    for account in account_list:
        if account["Service"] == service_to_delete:
            # Delete the account from the account list
            del account_list[index]
            break

        index += 1

    # Update the data for the username with the modified account list
    fetched_data[username] = account_list

    # Write the updated data back to the "db.json" file
    with open("db.json", "w") as updated_db:
        json.dump(fetched_data, updated_db, indent=2)


# Function to update the database with new account information
def update(user, user_name, service, encrypted_password):
    # Open the "db.json" file in read mode to fetch data
    with open("db.json", 'r') as fitch:
        fetched_data = json.load(fitch)

    # Create a new dictionary with the new account data
    new_account_data = {
        "User": user_name,
        "Service": service,
        "Password": encrypted_password.decode('latin-1')
    }

    try:
        # Try to append the new account data to the list associated with the user
        fetched_data[str(user)].append(new_account_data)
    except KeyError:
        # Handle the case where the user key doesn't exist in the database
        print("Please enter the correct username!!")
    finally:
        # Write the updated data back to the "db.json" file
        with open("db.json", "w") as update:
            json.dump(fetched_data, update, indent=2)



def argument_parser():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser()

    # Add command-line arguments to the parser

    # -i or --initiate: Expects one argument, the username for the password manager
    parser.add_argument('-i', '--initiate', nargs=1, help="-i <username for the password manager>")

    # -a or --add: Expects two arguments, the service name and the username on that service
    parser.add_argument('-a', '--add', nargs=2, help='-a <service name> <username on this service>')

    # -d or --delete: Expects one argument, the service name to be deleted
    parser.add_argument('-d', '--delete', nargs=1, help='-d <service name>')

    # -up or --update: Expects one argument, the service name to be updated
    parser.add_argument('-up', '--update', nargs=1, help='-up <service name>')

    # -r or --retrieve: Expects one argument, the service name to retrieve information
    parser.add_argument('-r', '--retrieve', nargs=1, help="-r <service name>")

    # Parse the command-line arguments and return the result
    return parser.parse_args()

def main():
    args = argument_parser()
    if args.initiate is not None:
     insialization(args.initiate[0])
    if args.add is not None:
     add_new_account(args.add[0],args.add[1])
    if args.update is not None:
        update_password(args.update[0])
    if args.retrieve is not None :
        retrieve_password(args.retrieve[0])

if __name__ == "__main__":
    main()
