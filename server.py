import sys
import socket
import json
import random
import datetime
import hashlib


sessions = dict()


def postRequest(msg, info, version, accountsFile): 
    with open(accountsFile, "r") as file:
        users = json.load(file)
   
    with open("passwords.json", "r") as passfile:
        passwords = json.load(passfile)


    if info.get('username') is None or info.get('password') is None:
        current = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current} LOGIN FAILED")
        resp = version + f" 501 Not Implemented\r\n"
        return resp
   
    #print("before hash: " + password + users[username][1])
    username = info.get('username')
    password = info.get('password')
     
    #print("after hash: " + hashed_password)
    #print("comparison: " + users[str(username)][0])
    if username in users and password in passwords:
        #set cookie to random 64bit hexadecimal value
        #if(username in users):
            #print("username valid")
        hashed_password = hashlib.sha256((password + users[username][1]).encode("ASCII")).hexdigest()
        #print(sessionID)
        #create session with required info for validation with cookie
        
        if hashed_password == users[username][0]:
            sessionID = format(random.getrandbits(64), '016x')
            sessions[sessionID] = {'username': username, 'timestamp': datetime.datetime.now().timestamp()} 
            username = info.get('username')
            password = info.get('password')   
            current = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            print(f"SERVER LOG: {current} LOGIN SUCCESSFUL: {username} : {password}")
            #return f"HTTP/1.0 200 OK\r\nSet-Cookie: sessionID = {sessionID}\r\n\r\n"
            #Logged in!\r\n\r\n'
            retStatement =  version + f" 200 OK\r\nSet-Cookie: sessionID={sessionID}\r\n\r\nLogged in!\r\n"
            #print(retStatement)
            return retStatement


        else:
            current = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            print(f"SERVER LOG: {current} LOGIN FAILED: {username} : {password}")
            resp = version + f" 200 OK\r\n\r\nLogin failed!\r\n"
            return resp
    else:
        username = info.get('username')
        password = info.get('password')
        current = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current} LOGIN FAILED: {username} : {password}")
        resp = version + " " + f"200 OK\r\n\r\nLogin failed!\r\n"
        return resp


def getRequest(target, version, sessionTimeout, rootDirectory, info, accountsFile):
   
    if not info.get('Cookie'):
        return "401 Unauthorized"
    
    blank, sessionID = info.get('Cookie').split("=")
    session = sessions.get(sessionID)

    if sessionID in sessions:
        username = sessions[sessionID].get("username")
        timestamp = sessions[sessionID].get("timestamp")
        time = datetime.datetime.now().timestamp()
        if time - float(timestamp) < float(sessionTimeout):
            session["timestamp"] = time


            filepath = f"{rootDirectory}{username}{target}"
            try:
                sFile = open(filepath, "r")
                info = sFile.read()
                currentTime = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                print(f"SERVER LOG: {currentTime} GET SUCCEEDED: {username} : {target}")
                resp = version + f" 200 OK\r\n\r\n{info}\r\n"
                return resp
               
            except FileNotFoundError:
                time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                print(f"SERVER LOG: {time} GET FAILED: {username} : {target}")
                resp =  version + " 404 Not Found\r\n"
                return resp
        else:
            time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            print(f"SERVER LOG: {time} SESSION EXPIRED: {username} : {target}")
            resp = version + " 401 Unauthorized\r\n"
            return resp
    else:
        time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {time} COOKIE INVALID : {target}")
        resp = version + " 401 Unauthorized\r\n"
        return resp

def start_server(ip, port, accountsFile, sessionTimeout, rootDirectory):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("Localhost", int(port)))
    s.listen()

    while True:    
        (socketUse, address) = s.accept()
        msg = socketUse.recv(1024).decode('ASCII').strip()
        method, target, version, info, message = getHTTP(msg)

        if method == "POST" and target == '/':
            response = postRequest(msg, info, version, accountsFile)
            socketUse.sendall(response.encode("ASCII"))
        elif method == "GET":
            response = getRequest(target,version, sessionTimeout, rootDirectory, info, accountsFile)
            socketUse.sendall(response.encode("ASCII"))
        else:
            response = version + "501 Not Implemented"
            socketUse.sendall(response.encode("ASCII"))
            return
        
        socketUse.close()
       
        #print(msg)
         
def getHTTP(msg):
    final = msg.split("\r\n")
    method, target, version = final[0].split(" ")
    info = {}

    for line in final[1:]:
        if not line:
            break
        key, value = line.split(": ", 1)
        info[key] = value

    message = final[-1] if final[-1] else None
    return method, target, version, info, message

if __name__== "__main__":
    if len(sys.argv) != 6:
            ##print(len(sys.argv))
        print("python3 server.py [IP] [PORT] [ACCOUNTS_FILE] [SESSION_TIMEOUT] [ROOT_DIRECTORY]")
        #print(len(sys.argv))
        sys.exit()     
    #print(len(sys.argv))

    ip, port, accountsFile, sessionTimeout, rootDirectory = sys.argv[1:6]
   
    start_server(ip, port, accountsFile, sessionTimeout, rootDirectory)



