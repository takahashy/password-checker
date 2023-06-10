# password_checker.py
# Yuma Takahashi

import requests
import hashlib
import sys

''' 
request_api
Purpose: Given the first 5 characters of the sha1 encrypted password 
         it returns the response provided by the haveibeenpwned API
'''
def request_api(query):
    url      = "https://api.pwnedpasswords.com/range/" + query
    response = requests.get(url)
    
    if (response.status_code != 200):
        print(f"\033[91mRUNTIME ERROR: Invalid request\033[0m")
        sys.exit(1)
    
    return response.text


'''
count_hacked
Purpose: Given the list of hashes from the API split them into a tuple of hash and the number
         of times it has been hacked. Match it with the tail to return the corresponding hacked count
'''
def count_hacked(hashes, tail):        
    hashed_pwords = (line.split(':') for line in hashes.splitlines())
    for hash, count in hashed_pwords:
        if hash == tail:
            return count
    return 0


'''
convert_to_hash
Purpose: Given the string convert it to a sha1 hash and 
         return it separated at the 5th character as a tuple
'''
def convert_to_hash(password):
    pword = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return pword[:5], pword[5:]
    
    
'''
read_file
Purpose: If a text file is given as another argument in the commandline 
         then read the passwords in the file
'''
def read_file(txtfile):
    try:
        with open(txtfile, 'r') as file:
            passwords = file.readlines()
            passwords = (word.replace('\n', '') for word in passwords)
            return passwords
    except FileNotFoundError:
        print(f"\033[91mFILE ERROR: \'{txtfile}\' was not found")
        sys.exit(1)
 
        
'''
main
Purpose: Runs the other functions to determine if the passwords passed in were 
         hacked or not
'''
def main(args):
    for arg in args:
        first, tail = convert_to_hash(arg)
        response = request_api(first)
        count = count_hacked(response, tail)
        if count:
            print(f"\033[91mYour password \'{arg}\' has been HACKED {count} times!! RECOMMEND USING A DIFFERENT PASSWORD\033[0m")
        else:
            print(f"\033[92mYour password \'{arg}\' has NOT been hacked! PROCEED WITH THAT PASSWORD\033[0m")    
    print("\nALL CHECKED")
        

# Run the program
if __name__ == '__main__':
    inputs = []
    if (len(sys.argv) > 1):
        inputs = read_file(sys.argv[1])
    else:
        inputs = input("Password: ").split(' ')
    
    main(inputs)
