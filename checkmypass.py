# importing necessary modules

import requests
import hashlib
import sys

# making a function to get a list of passwords from the api that matches our query of the first 5 chars
def request_api_data(query_char):
    """
        Make a request to the PwnedPasswords API to get a list of passwords that match the query.
        """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    # some error handling
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}')
    return res


# making a function to get all the matching hashed passwords and count how many times they were found
def get_password_leaks_count(hashes, hash_to_check):
    """
       Get the count of matching hashed passwords from the response.
       """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# function to locally check hashed passwords
def pwned_api_check(password):
    """
       Check if the given password has been pwned by querying the PwnedPasswords API.
       """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # breaking the password in two so that your whole password is only evaluated locally and not shared with the api.
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

# to run the program, in terminal type: python3 checkmypass.py password
def main(args):
    """
       Main function to check passwords against the PwnedPasswords API.
       """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times, you should probably change that")
        else:
            print(f"{password} was NOT found! how fab.")
    return "done!"

if __name__ == "__main__":
    main(sys.argv[1:])