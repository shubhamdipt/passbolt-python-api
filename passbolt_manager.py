import passboltapi
from colorama import Fore, init
import sys
import time
import argparse
import string
import random


def banner():
    print(Fore.CYAN + """
                     _           _ _         
 _ __   __ _ ___ ___| |__   ___ | | |_       
| '_ \ / _` / __/ __| '_ \ / _ \| | __|      
| |_) | (_| \__ \__ \ |_) | (_) | | |_       
| .__/ \__,_|___/___/_.__/ \___/|_|\__|____  
|_|                                  |_____| 
 _ __ ___   __ _ _ __   __ _  __ _  ___ _ __ 
| '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ \ '__|
| | | | | | (_| | | | | (_| | (_| |  __/ |   
|_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|   
                             |___/ @Pitenager          
    """)

    time.sleep(0.5)


def login():
    try:
        print(Fore.CYAN + "[*] Trying to authenticate against Passbolt server...")

        passbolt = passboltapi.PassboltAPI(config_path="config.ini", new_keys=True, delete_old_keys=True)
        uuid = passbolt.get(url="/resources.json?api-version=v2")["header"]["id"]

        print(Fore.GREEN + "[-] Authenticated")
        return passbolt,uuid

    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def generate_password():
    try:
        print(Fore.CYAN + "[*] Generating random password...")

        #Create alphanumerical from string constants
        printable = f'{string.ascii_letters}{string.digits}{string.punctuation}'

        #Convert printable from string to list and shuffle
        printable = list(printable)
        random.shuffle(printable)

        #Generate random password and convert to string
        random_password = random.choices(printable, k=16)
        random_password = ''.join(random_password)

        return random_password

    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def read(passbolt,name):
    try:
        print(Fore.CYAN + f"[*] Reading resource {name}...")

        for i in passbolt.get(url="/resources.json?api-version=v2")["body"]:
            if i["name"] == name:
                resource = passbolt.get("/secrets/resource/{}.json?api-version=v2".format(i["id"]))
                i["password"] = passbolt.decrypt(resource["body"]["data"])
                print(i)
                break
    
    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def upload(passbolt,uuid,name):
    try:
        pwd = generate_password()
        encrypted_pass = passbolt.encrypt(pwd)

        json_data = { 
            "name": name,
            "description": f"(Automated) {name} password",
            "secrets": [{
                "user_id": uuid,
                "data": encrypted_pass
            }]
        }

        print(Fore.CYAN + "[*] Uploading new password...")
        passbolt.post(url="/resources.json?api-version=v2",data=json_data)
        print(Fore.GREEN + "[-] Password uploaded")

    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def change(passbolt, name):
    try:
        pwd = generate_password()
        encrypted_pass = passbolt.encrypt(pwd)

        print(Fore.CYAN + f"[*] Changing password of resource {name}...")

        for i in passbolt.get(url="/resources.json?api-version=v2")["body"]:
            if i["name"] == name:
                json_data = { 
                    "name": name,
                    "description": f"(Automated) {name} password",
                    "secrets": [{
                        "user_id": i["created_by"],
                        "data": encrypted_pass
                    }]
                }
                resourceId = i["id"]
                passbolt.put(url=f"/resources/{resourceId}.json?api-version=v2",data=json_data)

        print(Fore.GREEN + f"[-] Password changed")

    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def delete(passbolt,name):
    try:
        print(Fore.CYAN + f"[*] Deleting resource {name}...")
        for i in passbolt.get(url="/resources.json?api-version=v2")["body"]:
            if i["name"] == name:
                resourceId = i["id"]
                break       
        passbolt.delete(url=f"/resources/{resourceId}.json?api-version=v2")
        print(Fore.GREEN + f"[-] Resource {name} deleted")
    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

def main(args):
    try:
        if (len(sys.argv) <= 1):    
            print(Fore.RED+"[!] Error: Should specify at least one argument")
            sys.exit(1)
        else:
            passbolt,uuid = login()
            if (args.change):
                change(passbolt, args.change)
            elif (args.upload):
                upload(passbolt, uuid, args.upload)
            elif (args.delete):
                delete(passbolt, args.delete)
            elif (args.read):
                read(passbolt, args.read)
            else:
                print(Fore.RED + "[!] Error: Invalid argument")
                sys.exit(1)

        print(Fore.CYAN + "[*] Closing session, exiting...")
        passbolt.close_session()
        print(Fore.GREEN + "[-] Session closed. Finished successfully")
        sys.exit(0)

    except Exception as e:
        print(Fore.RED + "[!] Error: " + str(e))
        sys.exit(1)

if __name__== "__main__":
    init(autoreset=True)
    banner()

    #Parameters
    parser = argparse.ArgumentParser(description="Client to operate Stratio's Passbolt server")
    parser.add_argument('-c', '--change', metavar="CHANGE", dest='change', default=False, help="Change an existing password in Passbolt")
    parser.add_argument('-u', '--upload', metavar="UPLOAD", dest='upload', default=False, help="Upload new password to Passbolt")
    parser.add_argument('-d', '--delete', metavar="DELETE", dest='delete', default=False, help="Delete an existing password in Passbolt")
    parser.add_argument('-r', '--read', metavar="READ", dest='read', default=False, help="Read an existing password in Passbolt")
    args = parser.parse_args()

    main(args)