import hashlib
import os
import sys
import requests

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code !=200:
        raise RuntimeError(f'Error fetching: {res.status_code}, Check the API and try again')
    return res

#Here we will hash our password
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char , tail = sha1password[:5],sha1password[5:]
    response = request_api_data(first5char)
    #print(first5char , tail)
    return read_res(response)

def read_res(response):
    print(response.text)

def get_password_leaks_count(hashes, hash_to_check):
    # hashes are all the returns that we got for our first5char
    # hash_to_check is our password that we want to check in our list of hashes
    #Lets first split the hashes into the hash itself and the count in a tuple
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h , count in hashes:
        if h == hash_to_check:
            return print(f'Your password has been used {count} times')
    return 0

#Using this function again to use our function above
def pwned_api_check_withpasswordcount(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char , tail = sha1password[:5],sha1password[5:]
    response = request_api_data(first5char)
    #print(first5char , tail)
    return get_password_leaks_count(response, tail)


#pwned_api_check('Letsdoit')
#print('Bro Lets differ')
pwned_api_check_withpasswordcount('BrosephStalin')

def main(args):
    for password in args:
        count = pwned_api_check_withpasswordcount(password)
        if count:
            print(f' {password} was found {count} times . . . You should change it')
        else:
            print(f'{password} was not found, Carry on!!')
    return 'done!'

main(sys.argv[1:])
