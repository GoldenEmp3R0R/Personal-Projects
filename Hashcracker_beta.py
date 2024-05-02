#!/usr/bin/python3

import hashlib

def crack_hashes(hash_file, password_list_file, output_file):
    # Read the hash file
    with open(hash_file, 'r') as file:
        hashes = file.readlines()

    # Read the password list file
    with open(password_list_file, 'r') as pass_file:
        password_list = pass_file.read().splitlines()

    # Open the output file in write mode
    with open(output_file, 'w') as output:
        for hash_value in hashes:
            hash_value = hash_value.strip()
            hash_length = len(hash_value)

            if hash_length == 32:
                algorithm = 'md5'
            elif hash_length == 40:
                algorithm = 'sha1'
            elif hash_length == 56:
                algorithm = 'sha224'
            elif hash_length == 64:
                algorithm = 'sha256'
            elif hash_length == 128:
                algorithm = 'sha512'
            else:
                # If the hash length doesn't match any known algorithms, skip
                continue
            
            # Try to crack the hash using the given algorithm
            try:
                matched_password = None
                for password in password_list:
                    # Encode the password string to bytes
                    password_bytes = password.encode('utf-8')

                    # Hash the password using the selected algorithm
                    hashed_password = hashlib.new(algorithm, password_bytes).hexdigest()

                    # Compare the hashed password with the hash value from the file
                    if hashed_password == hash_value:
                        matched_password = password
                        break

                # If a matching password is found, write the result to the output file
                if matched_password:
                    decoded_hash = hashlib.new(algorithm, matched_password.encode('utf-8')).hexdigest()
                    output.write(f"{matched_password}\n")

            except Exception as e:
                pass


hash_file = 'hashes.txt'
password_list_file = 'passwordList.txt'
output_file = 'decoded_hashes.txt'

crack_hashes(hash_file, password_list_file, output_file)

print("Decoded hashes written to 'decoded_hashes.txt'")

