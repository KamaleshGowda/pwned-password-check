#check pwned password using text file

import requests
import hashlib
import sys

def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check api')
  return res

def get_pass_leak_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0


def pwned_api_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_pass_leak_count(response, tail)

def main(filename):
  try:
    with open(filename, 'r') as file:
        passwords = file.readlines()
  except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
  except IOError as e:
    print(f"Error: {e}")

  for password in passwords:
    password = password.strip('\n')
    count = pwned_api_check(password)
    if count:
      print(f'{password} was found {count} times. Changing password is suggested!')
    else:
      print(f'{password} was not found! Go ahead.')
  print('Thankyou!')


if __name__ == '__main__':
  main(sys.argv[1])