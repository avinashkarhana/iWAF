# -*- coding: utf-8 -*-
import sys
import socket
import _thread as thread
from xml.dom.expatbuilder import parseString
import requests
import json
import sqlite3
import time
import traceback
#from gevent import monkey; monkey.patch_all()
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from utils import SPECIAL_CHARACTER_HTML_MAPPING, CommonSQLInjectionRules
from __init__ import __version__
from defaultConfig import *

USAGE_STRING = """Usage: python3 waf.py [...options]
Options:
    port=8080               [ Port to listen on (default 8080) ]
    host=localhost          [ Host to listen on (default all) ]
    debug=True              [ Debug mode to see all debug messages ]
    profileId=1             [ Profile ID to use ]
    --help                  [ Show this help message ]
    --version               [ Show version ]    
"""

# Instance Holder of Intelligent class
intelligentPredictor = None

IPCache = {}

def getIpInfo(ip):
    global IPCache
    if ip not in IPCache:
        url = "http://ip-api.com/json/" + ip + '?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,mobile,proxy,hosting'
        resp = str(requests.get(url,'30').content)[2:-1]
        IpInfo = json.loads(str(resp))
        IPCache[ip] = IpInfo
    else:
        IpInfo = IPCache[ip]
    return(IpInfo)

#working thread START
def filterThread(conn, clientAddress):
    # get client IP Info
    ipDetails = getIpInfo(str(clientAddress[0]))
    #set essential dict keys if status fail
    if ipDetails['status'] == 'fail':
        IpDetailFields = ["status","message","country","countryCode","region","regionName","city","district","zip","lat","lon","timezone","currency","isp","org","as","mobile","proxy","hosting"]
        for b in IpDetailFields:
            if b != 'status':
                ipDetails[b] = ''

    # capture request from client
    request = conn.recv(MAX_RCV)
    result = request.find(b'\r\n\r\n')

    # reject self looping request when firewall and application host:port are set same by mistake
    if (FIREWALL_HOST == CURRENT_SERVER_HOST and FIREWALL_PORT == CURRENT_SERVER_PORT) or (FIREWALL_HOST == '' and CURRENT_SERVER_HOST == '127.0.0.1' and FIREWALL_PORT == CURRENT_SERVER_PORT):
        send_response(
            conn,
            b"\r\nHTTP/1.1 200 OK\r\n\r\n<h1>Snake is biting it's own Tail !!</h1>\r\n",
        )

    # get the first line of request
    reqFirstLine = request.split(b'\n')[0]

    # get first part of request with GET data and other things like url request type etc.
    reqFirstPart = request[:result+4]
    # get last part of request with POST data etc.
    reqLastPart = request[result+4:]

    failAttemptMsg = b"\r\nHTTP/1.1 200 OK\r\n\r\nWeb Application Firewall Detected Suspicious activity !!\r\n"

    ###################################################
    ###############Apply WAF rules START###############
    ###################################################

    # Country based filtering START
    try:
        if (
            OnlyAllowedCountries
            and ipDetails['countryCode'] not in ALLOWED_COUNTRIES
            or not OnlyAllowedCountries
            and ipDetails['countryCode'] in BLOCKED_COUNTRY
        ):
            printInfoOut("[BLOCKED]Country Blocked(" + ipDetails['country'] + ")", reqFirstLine, clientAddress)
            send_response(
                conn,
                b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service is not available in your country !!</h1>\r\n',
            )

    except SystemExit:
        sys.exit(1)
    except:
        trace("Country based filtering Failed !")
    # Country based filtering END

    # check PROXY IPs START
    try:
        if ipDetails['proxy'] == True and PROXY_BLOCK:
            printInfoOut("[BLOCKED]PROXY IP", reqFirstLine, clientAddress)
            send_response(
                conn,
                b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service can not be used with proxy !!</h1>\r\n',
            )

    except SystemExit:
        sys.exit(1)
    except:
        trace("Proxy IP check Failed !")
    # check PROXY IPs END

    # IP Based Filtering START
    try:
        if (
            OnlyAllowedIP
            and clientAddress[0] not in ALLOWED_CLIENTS
            or not OnlyAllowedIP
            and clientAddress[0] in BLOCKED_CLIENTS
        ):
            printInfoOut("[BLOCKED]IP Blacklisted", reqFirstLine, clientAddress)
            send_response(
                conn,
                b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>IP Blacklisted !!</h1>\r\n',
            )

    except SystemExit:
        sys.exit(1)
    except:
        trace("IP Based Filtering Failed !")
    # IP Based Filtering END

    #special Character Sanitization START
    try:
        for key, value in SPECIAL_CHARACTER_HTML_MAPPING.items():
            reqLastPart = reqLastPart.replace(key.encode('utf-8'), value.encode('utf-8'))
    except SystemExit:
        sys.exit(1)
    except:
        trace("Special Character Sanitization Failed !")
    #special Character Sanitization END

    #SQL Injection Check START
    try:
        reqLastPart = reqLastPart.upper()
        for rule in CommonSQLInjectionRules:
            if rule in reqLastPart :
                conn.send(failAttemptMsg)
                conn.close()
                printInfoOut("[BLOCKED]SQL Injection", reqFirstLine, clientAddress)
                with open('intrusion.log','a+') as intrusionLogFile:
                    intrusionLogFile.write("\nSQL Injection(REGEX)❡" + str(reqFirstLine) + "❡" + str(clientAddress[0]) + ":" + str(clientAddress[1]) + "❡" + str(reqFirstPart+reqLastPart) + "\n")
                try:
                    sys.exit(1)
                except SystemExit:
                    sys.exit(1)
                except:
                    if DEBUG:
                        traceback.print_exc()

        reqFirstLine = reqFirstLine.upper()
        for rule in CommonSQLInjectionRules:
            if rule in reqFirstLine :
                conn.send(failAttemptMsg)
                conn.close()
                printInfoOut("[BLOCKED]SQL Injection", reqFirstLine, clientAddress)
                with open('intrusion.log','a+') as intrusionLogFile:
                    intrusionLogFile.write("\nSQL Injection(REGEX)❡" + str(reqFirstLine)+"❡" + str(clientAddress[0])+":" + str(clientAddress[1]) + "❡" + str(reqFirstPart + reqLastPart))
                try:
                    sys.exit(1)
                except SystemExit:
                    sys.exit(1)
                except:
                    if DEBUG:
                        traceback.print_exc()

        reqFirstPart = reqFirstPart.replace(b'&frasl;', b'/')
        request = reqFirstPart + reqLastPart
    except SystemExit:
        sys.exit(1)
    except:
        trace("SQL Injection Check Failed !")
    #SQL Injection Check END

    #Intelligent Request Testing START
    try:
        if INTELLIGENT_REQ_TEST:
            #check reqLastPart for POST type requests
            global intelligentPredictor
            if len(str(reqLastPart)) > 3:
                try:
                    intelligentPredResult = intelligentPredictor.predictSqliAttack(input_val=reqLastPart)
                    if intelligentPredResult > INTELLIGENT_THRESHOLD[INTELLIGENT_MODE.upper()]:
                        conn.send(failAttemptMsg + b'i')
                        conn.close()
                        printInfoOut("[BLOCKED]Intelligent System Marked Request as SQL Injection", reqFirstLine, clientAddress)
                        with open('intrusion.log','a+') as intrusionLogFile:
                            intrusionLogFile.write("\nSQL Injection(INTELLIGENT)❡" + str(reqFirstLine) + "❡" + str(clientAddress[0])+ ":" + str(clientAddress[1]) + "❡" + str(reqFirstPart+reqLastPart))
                        try:
                            sys.exit(1)
                        except SystemExit:
                            sys.exit(1)
                        except:
                            if DEBUG:
                                traceback.print_exc()
                except:
                    if DEBUG:
                        traceback.print_exc()
            # check reqFirstLine for GET type requests
            if len(str(reqFirstLine)) > 3:
                try:
                    tu = str(reqFirstLine).split(" ")[1].split("?")[1]
                    intelligentPredResult = intelligentPredictor.predictSqliAttack(input_val=tu)
                    if intelligentPredResult > INTELLIGENT_THRESHOLD[INTELLIGENT_MODE.upper()]:
                        conn.send(failAttemptMsg + b'i')
                        conn.close()
                        printInfoOut("[BLOCKED]Intelligent System Marked Request as SQL Injection", reqFirstLine, clientAddress)
                        with open('intrusion.log', 'a+') as intrusionLogFile:
                            intrusionLogFile.write("\nSQL Injection(INTELLIGENT)❡" + str(reqFirstLine) + "❡" + str(clientAddress[0])+ ":" + str(clientAddress[1]) + "❡" + str(reqFirstPart+reqLastPart))
                        try:
                            sys.exit(1)
                        except SystemExit:
                            sys.exit(1)
                        except:
                            if DEBUG:
                                traceback.print_exc()
                except:
                    if DEBUG:
                        traceback.print_exc()
    except SystemExit:
        sys.exit(1)
    except:
        trace('Failed Intelligent Request Testing !')
    #Intelligent Request Testing END


    ###################################################
    ###############Apply WAF rules END#################
    ###################################################

    # LOGGING START
    try:
        if ipDetails['status']=='fail':
            IPData = ""
        else:
            IPData = " Country : " + ipDetails['country'] + " (" + ipDetails['regionName'] + ")"
            if ipDetails['proxy'] == 'true':
                IPData += " [PROXY]"
        ipAddress = [clientAddress[0]]
        ipAddress[0] += IPData
        printInfoOut("Request", reqFirstLine, ipAddress)
    except:
        trace("Logging Failed !")
    # LOGGING END

    #Web Application address
    webApplicationServer = CURRENT_SERVER_HOST
    #Web Application port
    port = ":" + str(CURRENT_SERVER_PORT) if int(CURRENT_SERVER_PORT) != 80 else ""
    #replace WAF server with actual server in request
    try:
        second_line = request.split(b'\n')[1].split(b" ")[1][:-1]
        request = request.replace(second_line,(webApplicationServer+str(port)).encode('utf-8'))
    except:
        trace("Could not replace server with actual server in request but, still trying to send!")

    #Inject True-Client-IP in headers
    try:
        if len(request.split(b'\n')) > 1:
            reqLastPart = b'\r\n' + request[request.find(request.split(b'\n')[1]):]
        else:
            reqLastPart = ''
        request = request.split(b'\n')[0][:-1] + b'\r\nTrue-Client-IP: ' + (str(clientAddress[0]).encode('utf-8')) + reqLastPart
    except:
        trace("Failed to Inject True-Client-IP")

    #Create a WEB APPLICATION SOCKET to send request to actual web application
    try:
        # web application connection Socket that can handle https
        webSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        webSocket.connect((webApplicationServer, int(CURRENT_SERVER_PORT)))
        # send request
        webSocket.send(request)

        while 1:
            # data from web application
            data = webSocket.recv(MAX_RCV)

            if (len(data) > 0):
                # data revert back to client
                conn.send(data)
            else:
                break
        webSocket.close()
        conn.close()
    except (socket.error):
        if webSocket:
            webSocket.close()
        if conn:
            conn.close()
        printInfoOut("Session Reset", reqFirstLine, clientAddress)
        try:
            sys.exit(1)
        except SystemExit:
            sys.exit(1)
        except:
            if DEBUG:
                traceback.print_exc()

def send_response(conn, msg):
    conn.send(msg)
    conn.close()
    try:
        sys.exit(1)
    except SystemExit:
        sys.exit(1)
    except:
        if DEBUG:
            traceback.print_exc()
# working thread END

#function for rowFactory of sqlite fetch
def dictFactory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

# thread : update rules from database
def dbRuleUpdateThread(profileId=None):
    force = True
    if profileId is None:
        profileId = 1
        force = False
    #creating connection to Sqlite3 Database
    try:
        dbFileContainerPath = "./iwaf/"
        dbFileContainerPath = ""
        conn = sqlite3.connect(dbFileContainerPath + 'waf.db')
        conn.row_factory = dictFactory
        while True:
            #updating profileID
            try:
                if not force:
                    dbConnectionCursor = conn.cursor()
                    dbConnectionCursor.execute("SELECT profID FROM CURRENT_PROFILE")
                    queryResponse = dbConnectionCursor.fetchone()
                    dbConnectionCursor.close()
                    profileId = queryResponse['profID']
            except:
                traceback.print_exc()
            #updating server host and port
            try:
                dbConnectionCursor = conn.cursor()
                dbConnectionCursor.execute("SELECT host,port FROM CURRENT_SERVER")
                queryResponse=dbConnectionCursor.fetchone()
                dbConnectionCursor.close()
                global CURRENT_SERVER_HOST
                global CURRENT_SERVER_PORT
                CURRENT_SERVER_HOST=queryResponse['host']
                CURRENT_SERVER_PORT=queryResponse['port']
            except:
                traceback.print_exc()
            if profileId is None:
                profileId=1
            try:
                dbConnectionCursor = conn.cursor()
                dbConnectionCursor.execute("SELECT * FROM WAF_RULES WHERE profID=" + str(profileId))
                queryResponse = dbConnectionCursor.fetchall()
                dbConnectionCursor.close()
                if len(queryResponse) < 1:
                    raise Exception('No such Profile !')
                else:
                    profile = queryResponse[0]
                #check for OnlyAllowedIP flag
                if profile['OnlyAllowedIP'] == 1:
                    global OnlyAllowedIP
                    if OnlyAllowedIP == False:
                        trace('Changed OnlyAllowedIP Flag to True')
                    global ALLOWED_CLIENTS
                    OnlyAllowedIP = True
                    #update ALLOWED_CLIENTS list as per profile
                    dbConnectionCursor = conn.cursor()
                    ALLOWED_CLIENTS = []
                    dbConnectionCursor.execute("SELECT ip FROM ipClients WHERE status=1 AND profID="+str(profileId))
                    queryResponse = dbConnectionCursor.fetchall()
                    queryRespIps = [k['ip'] for k in queryResponse]
                    ALLOWED_CLIENTS += queryRespIps
                    dbConnectionCursor.close()
                else:
                    if OnlyAllowedIP:
                        trace('Changed OnlyAllowedIP Flag to False')
                    OnlyAllowedIP = False
                #check for OnlyAllowedCountry flag
                if profile['onlyAllowedCountries'] == 1:
                    global OnlyAllowedCountries
                    if OnlyAllowedCountries == False:
                        trace('Changed OnlyAllowedCountries Flag to True')
                    global ALLOWED_COUNTRIES
                    OnlyAllowedCountries = True
                    #update ALLOWED_CLIENTS list as per profile
                    dbConnectionCursor = conn.cursor()
                    ALLOWED_COUNTRIES = []
                    dbConnectionCursor.execute("SELECT countryCode FROM COUNTRY_RULE WHERE status=1 AND profID="+str(profileId))
                    queryResponse = dbConnectionCursor.fetchall()
                    queryRespIps = [k['countryCode'] for k in queryResponse]
                    ALLOWED_COUNTRIES += queryRespIps
                    dbConnectionCursor.close()
                else:
                    if OnlyAllowedCountries:
                        trace('Changed OnlyAllowedCountries Flag to False')
                    OnlyAllowedCountries = False
                #check for Proxy Block flag
                if profile['proxyBlock'] == 1:
                    global PROXY_BLOCK
                    if PROXY_BLOCK == False:
                        trace('Changed ProxyBlock Flag to True')
                    PROXY_BLOCK = True
                else:
                    if PROXY_BLOCK:
                        trace('Changed ProxyBlock Flag to False')
                    PROXY_BLOCK = False
                #check for intelligent test flag
                if profile['intelligentTest'] == 1:
                    global INTELLIGENT_REQ_TEST
                    if INTELLIGENT_REQ_TEST == False:
                        trace('Changed INTELLIGENT_REQ_TEST Flag to True')
                    INTELLIGENT_REQ_TEST = True
                else:
                    if INTELLIGENT_REQ_TEST:
                        trace('Changed INTELLIGENT_REQ_TEST Flag to False')
                    INTELLIGENT_REQ_TEST = False

                #set number of request to hold
                global REQUEST_HOLD
                REQUEST_HOLD = int(profile['requestHold'])

                #set Intelligent Mode
                global INTELLIGENT_MODE
                if profile['intelligentMode'] != "NULL":
                    INTELLIGENT_MODE = profile['intelligentMode']

                #set max request size
                global MAX_RCV
                MAX_RCV = int(profile['maxRcv'])

                #check for BLOCKED CLIENTS
                global BLOCKED_CLIENTS
                dbConnectionCursor = conn.cursor()
                BLOCKED_CLIENTS = []
                dbConnectionCursor.execute("SELECT ip FROM ipClients WHERE status=0 AND profID="+str(profileId))
                queryResponse = dbConnectionCursor.fetchall()
                queryRespIps = [k['ip'] for k in queryResponse]
                BLOCKED_CLIENTS += queryRespIps
                dbConnectionCursor.close()

                #check blocked Countries
                global BLOCKED_COUNTRY
                dbConnectionCursor = conn.cursor()
                BLOCKED_COUNTRY = []
                dbConnectionCursor.execute("SELECT countryCode FROM COUNTRY_RULE WHERE status=0 AND profID="+str(profileId))
                queryResponse = dbConnectionCursor.fetchall()
                queryRespIps = [k['countryCode'] for k in queryResponse]
                BLOCKED_COUNTRY += queryRespIps
                dbConnectionCursor.close()
            except:
                profileId=profileId = (1,)
                traceback.print_exc()
                trace('No Such profile as'+str(profileId)+"Using Default profile !")
            time.sleep(3)
        conn.commit()
        conn.close()
    except:
        if DEBUG:
            traceback.print_exc()
        print("Failed to connect to database, using in-file rules!")

#Output info if DEBUG true and color code as per rule hit
def printInfoOut(requestType, request, requestFrom):
    if DEBUG:
        if requestType == "Request":clr = 34
        elif "[BLOCKED]IP Blacklist" in requestType:clr = 33
        elif "[BLOCKED]SQL Injection" in requestType: clr=31
        elif "[BLOCKED]Intelligent System Marked Request as SQL Injection" in requestType:clr=31
        elif "[BLOCKED]PROXY IP" in requestType: clr=32
        elif "[BLOCKED]Country Blocked" in requestType: clr=32
        else:clr=30
        trace ("\033["+str(clr)+"m"+str(requestFrom[0])+"\t"+str(requestType)+"\t"+str(request)+"\033[0m")

#Output on DEBUG true
def trace(stringData):
    if DEBUG:
        print(stringData)

#main function definition
def main():
    global FIREWALL_HOST
    global FIREWALL_PORT
    global DEBUG
    global ENVIRONMENT
    
    profileID = None
    
    for i in range(len(sys.argv)):
        arg = sys.argv[i]
        # if i ==0 and arg is number then set port to arg
        if i == 1 and arg.isdigit():
            FIREWALL_PORT = int(arg)
        try:
            if arg.split("=")[0].lower() == "debug" and arg.split("=")[1].lower() == "true":
                DEBUG = True
            if arg.split("=")[0].lower() == "port":
                FIREWALL_PORT = int(arg.split("=")[1])
            if arg.split("=")[0].lower() == "host":
                FIREWALL_HOST = arg.split("=")[1]
            if arg.split("=")[0].lower() == "profileId".lower():
                profileID = arg.split("=")[1]
            if "help" in arg.split("=")[0].lower():
                print(USAGE_STRING)
                sys.exit(0)
            if "version" in arg.split("=")[0].lower():
                print(__version__)
                sys.exit(0)
        except:
            print("Invalid Argument !")
            print(USAGE_STRING)
            exit(1)

    # start thread to get updates from database
    try:
        thread.start_new_thread(dbRuleUpdateThread, (profileID,))
    except SystemExit:
        sys.exit(1)
    except:
        print("Could not start thread for database Updates!\n#########Running on in-file rules !#########")

    print ("WAF Server Running on ", FIREWALL_HOST, ":", FIREWALL_PORT)
    wafWebSocket = None

    print("Running in Development Mode !")
    try:
        wafWebSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set address and port reuse
        wafWebSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to host and port
        wafWebSocket.bind((FIREWALL_HOST, FIREWALL_PORT))
        # start listening
        wafWebSocket.listen(REQUEST_HOLD)

    except socket.error as e:
        if wafWebSocket:
            wafWebSocket.close()
        trace ("Error while opening socket : "+ str(e))
        try:
            sys.exit(1)
        except SystemExit:
            sys.exit(1)
        except:
            if DEBUG:
                traceback.print_exc()

    # instantiate the intelligent system
    from intelligent.SQLiPredictor import Intelligent
    global intelligentPredictor
    intelligentPredictor = Intelligent() 
    
    # connections from client
    while True:
        conn, client_addr = wafWebSocket.accept()
        print("Connection from", client_addr)
        # request handling thread creation
        thread.start_new_thread(filterThread, (conn, client_addr))
    wafWebSocket.close()

if __name__ == '__main__':
    main()
    try:
      main()
    except KeyboardInterrupt:
      sys.exit(0)
    except:
        if DEBUG:
            traceback.print_exc()
