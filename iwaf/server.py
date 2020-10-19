# -*- coding: utf-8 -*-
import sys
import socket
import _thread as thread
import requests
import json
import sqlite3
import time
from intelligent.SQLiPredictor import Intelligent
import traceback
#creating instance of Intelligent class
zop = Intelligent() 

####################################################################
####################### Default Configuration START#################
####################################################################
FIREWALL_PORT=8080
FIREWALL_HOST=''
CURRENT_SERVER_HOST="online.hnbgu.ac.in" # Current application server host
CURRENT_SERVER_PORT=80       # Current application port
DEBUG = False                # debug mode to see all debug messages
ALLOWED_CLIENTS = []         # Allowed Clients
BLOCKED_CLIENTS = []         # BLOCKED clients
REQUEST_HOLD = 50            # number connections to hold
MAX_RCV = 999999             # max number data bytes to receive
PROXY_BLOCK = False           # Block access through known Web Proxy or VPN
INTELLIGENT_REQ_TEST = False # Intelligent request testing via Machine Learning (Increases Response time!)
OnlyAllowedCountries = False # Check for only allowed countries rule
OnlyAllowedIP = False        # Check for only allowed IP rule
ALLOWED_COUNTRIES = []       # Allowed Access in specific countries via IP geo location
BLOCKED_COUNTRY = []         # Blocked Access in specific countries via IP geo location
INELLIGENT_MODE = 'NORMAL'   # Intelligent mode
INTELLIGENT_THRESHOLD={'NORMAL':.50,'HARD':0.481,'UNDER-ATTACK':.441} # Intelligent Threshold values as per modes
####################################################################
####################### Default Configuration END###################
####################################################################

Special_Chars_HTML_code={ "(":"&#40;",")":"&#41;",'"':"&quot;","'":"&apos;","&":"&amp;","<":"&lt;",">":"&gt;","Œ":"&OElig;","œ":"&oelig;","Š":"&Scaron;","š":"&scaron;","Ÿ":"&Yuml;","ƒ":"&fnof;","ˆ":"&circ;","˜":"&tilde;"," ":"&ensp;"," ":"&emsp;"," ":"&thinsp;","‌":"&zwnj;","‍":"&zwj;","‎":"&lrm;","‏":"&rlm;","–":"&ndash;","—":"&mdash;","‘":"&lsquo;","’":"&rsquo;","‚":"&sbquo;","“":"&ldquo;","”":"&rdquo;","„":"&bdquo;","†":"&dagger;","‡":"&Dagger;","•":"&bull;","…":"&hellip;","‰":"&permil;","′":"&prime;","″":"&Prime;","‹":"&lsaquo;","›":"&rsaquo;","‾":"&oline;","€":"&euro;","™":"&trade;","←":"&larr;","↑":"&uarr;","→":"&rarr;","↓":"&darr;","↔":"&harr;","↵":"&crarr;","⌈":"&lceil;","⌉":"&rceil;","⌊":"&lfloor;","⌋":"&rfloor;","◊":"&loz;","♠":"&spades;","♣":"&clubs;","♥":"&hearts;","♦":"&diams;","∀":"&forall;","∂":"&part;","∃":"&exist;","∅":"&empty;","∇":"&nabla;","∈":"&isin;","∉":"&notin;","∋":"&ni;","∏":"&prod;","∑":"&sum;","−":"&minus;","∗":"&lowast;","√":"&radic;","∝":"&prop;","∞":"&infin;","∠":"&ang;","∧":"&and;","∨":"&or;","∩":"&cap;","∪":"&cup;","∫":"&int;","∴":"&there4;","∼":"&sim;","≅":"&cong;","≈":"&asymp;","≠":"&ne;","≡":"&equiv;","≤":"&le;","≥":"&ge;","⊂":"&sub;","⊃":"&sup;","⊄":"&nsub;","⊆":"&sube;","⊇":"&supe;","⊕":"&oplus;","⊗":"&otimes;","⊥":"&perp;","⋅":"&sdot;","Α":"&Alpha;","Β":"&Beta;","Γ":"&Gamma;","Δ":"&Delta;","Ε":"&Epsilon;","Ζ":"&Zeta;","Η":"&Eta;","Θ":"&Theta;","Ι":"&Iota;","Κ":"&Kappa;","Λ":"&Lambda;","Μ":"&Mu;","Ν":"&Nu;","Ξ":"&Xi;","Ο":"&Omicron;","Π":"&Pi;","Ρ":"&Rho;","Σ":"&Sigma;","Τ":"&Tau;","Υ":"&Upsilon;","Φ":"&Phi;","Χ":"&Chi;","Ψ":"&Psi;","Ω":"&Omega;","α":"&alpha;","β":"&beta;","γ":"&gamma;","δ":"&delta;","ε":"&epsilon;","ζ":"&zeta;","η":"&eta;","θ":"&theta;","ι":"&iota;","κ":"&kappa;","λ":"&lambda;","μ":"&mu;","ν":"&nu;","ξ":"&xi;","ο":"&omicron;","π":"&pi;","ρ":"&rho;","ς":"&sigmaf;","σ":"&sigma;","τ":"&tau;","υ":"&upsilon;","φ":"&phi;","χ":"&chi;","ψ":"&psi;","ω":"&omega;","ϑ":"&thetasym;","ϒ":"&upsih;","ϖ":"&piv;","À":"&Agrave;","Á":"&Aacute;","Â":"&Acirc;","Ã":"&Atilde;","Ä":"&Auml;","Å":"&Aring;","Æ":"&AElig;","Ç":"&Ccedil;","È":"&Egrave;","É":"&Eacute;","Ê":"&Ecirc;","Ë":"&Euml;","Ì":"&Igrave;","Í":"&Iacute;","Î":"&Icirc;","Ï":"&Iuml;","Ð":"&ETH;","Ñ":"&Ntilde;","Ò":"&Ograve;","Ó":"&Oacute;","Ô":"&Ocirc;","Õ":"&Otilde;","Ö":"&Ouml;","Ø":"&Oslash;","Ù":"&Ugrave;","Ú":"&Uacute;","Û":"&Ucirc;","Ü":"&Uuml;","Ý":"&Yacute;","Þ":"&THORN;","ß":"&szlig;","à":"&agrave;","á":"&aacute;","â":"&acirc;","ã":"&atilde;","ä":"&auml;","å":"&aring;","æ":"&aelig;","è":"&egrave;","é":"&eacute;","ê":"&ecirc;","ë":"&euml;","ì":"&igrave;","í":"&iacute;","î":"&icirc;","ï":"&iuml;","ð":"&eth;","ñ":"&ntilde;","ò":"&ograve;","ó":"&oacute;","ô":"&ocirc;","õ":"&otilde;","ö":"&ouml;","ø":"&oslash;","ù":"&ugrave;","ú":"&uacute;","û":"&ucirc;","ü":"&uuml;","ý":"&yacute;","þ":"&thorn;","ÿ":"&yuml;","¡":"&iexcl;","¢":"&cent;","¥":"&yen;","§":"&sect;","©":"&copy;","ª":"&ordf;","«":"&laquo;","¬":"&not;","®":"&reg;","¯":"&macr;","°":"&deg;","±":"&plusmn;","²":"&sup2;","³":"&sup3;","´":"&acute;","µ":"&micro;","¶":"&para;","·":"&middot;","¸":"&cedil;","¹":"&sup1;","º":"&ordm;","»":"&raquo;","¼":"&frac14;","½":"&frac12;","¾":"&frac34;","¿":"&iquest;","×":"&times;","÷":"&divide;"}
ipdetailFileds=["status","message","country","countryCode","region","regionName","city","district","zip","lat","lon","timezone","currency","isp","org","as","mobile","proxy","hosting"]
SQL_Injection_Rules=[ b'%2BAND%28UNION', b'%2BAND%2BUNION%28', b'UNION%2BSELECT', b'||%2B%28SELECT', b'||%2BSUBSTR(', b'+AND+UNION', b'+AND+UNION(', b'UNION+SELECT', b'||+(SELECT', b'||+SUBSTR(' ,b' AND UNION', b' AND UNION(', b'UNION SELECT', b'UNION%20SELECT', b'|| (SELECT', b'|| SUBSTR(' ]
ipcache={}

def ipinfo(ip):
    if ip not in ipcache:
        url="http://ip-api.com/json/"+ip+'?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,mobile,proxy,hosting'
        z=str(requests.get(url,'30').content)[2:-1]
        resp=json.loads(str(z))
        ipcache[ip]=resp
    else:
        resp=ipcache[ip]
    return(resp)

#working thread START
def prthread(conn, client_addr):
    # get client IP Info
    ipdetails=ipinfo(str(client_addr[0]))
    #set essential dict keys if status fail
    if ipdetails['status']=='fail':
        for b in ipdetailFileds:
            if b!='status':
                ipdetails[b]=''

    # capture request from client
    request = conn.recv(MAX_RCV)
    result = request.find(b'\r\n\r\n')

    # reject selflooping request when firewall and application host:port are set same by mistake
    if (FIREWALL_HOST==CURRENT_SERVER_HOST and FIREWALL_PORT==CURRENT_SERVER_PORT) or (FIREWALL_HOST=='' and CURRENT_SERVER_HOST=='127.0.0.1' and FIREWALL_PORT==CURRENT_SERVER_PORT):
        conn.send(b"\r\nHTTP/1.1 200 OK\r\n\r\n<h1>Snake is biting it's own Tail !!</h1>\r\n")
        conn.close()
        try:sys.exit(1)
        except SystemExit:sys.exit(1)
        except:pass
    
    # parse the first line
    first_line = request.split(b'\n')[0]

    sta=request[:result+4]
    act=request[result+4:]

    failattemtmsg=b"Web Application Firewall Detected Suspecious activity !!\r\n"
    
    ###################################################
    ###############Apply WAF rules START###############
    ###################################################

    # Country based filtering START
    try:
        if OnlyAllowedCountries:
            if ipdetails['countryCode'] not in ALLOWED_COUNTRIES:
                infoOut("[BLOCKED]Country Blocked("+ipdetails['country']+")",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service is not available in your country !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass
        else:
            if ipdetails['countryCode'] in BLOCKED_COUNTRY:
                infoOut("[BLOCKED]Country Blocked("+ipdetails['country']+")",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service is not available in your country !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass
    except SystemExit:sys.exit(1)
    except:
        trace("Country based filtering Failed !")
    # Country based filtering END

    # check PROXY IPs START
    try:
        if ipdetails['proxy']==True and PROXY_BLOCK:
            infoOut("[BLOCKED]PROXY IP",first_line,client_addr)
            conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service can not be used with proxy !!</h1>\r\n')
            conn.close()
            try:sys.exit(1)
            except SystemExit:sys.exit(1)
            except:pass
    except SystemExit:sys.exit(1)
    except:
        trace("Proxy IP check Failed !")
    # check PROXY IPs END

    # IP Based Filtering START
    try:
        if OnlyAllowedIP:
            if client_addr[0] not in ALLOWED_CLIENTS:
                infoOut("[BLOCKED]IP Blacklisted",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>IP Blacklisted !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass
        else:
            if client_addr[0] in BLOCKED_CLIENTS:
                infoOut("[BLOCKED]IP Blacklisted",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>IP Blacklisted !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass
    except SystemExit:sys.exit(1)
    except:
        trace("IP Based Filtering Failed !")
    # IP Based Filtering END

    #special Character Sanitisation START
    try:
        for key, value in Special_Chars_HTML_code.items():
            act=act.replace(key.encode('utf-8'),value.encode('utf-8'))
    except SystemExit:sys.exit(1)
    except:
        trace("Special Character Sanitization Failed !")
    #special Character Sanitisation END
    
    #SQL Injection Check START
    try:
        act1=act.upper()
        zw=SQL_Injection_Rules
        for qw in zw:
            if qw in act1 :
                conn.send(failattemtmsg)
                conn.close()
                infoOut("[BLOCKED]SQL Injection",first_line,client_addr)
                with open('intrusion.log','a+') as intrusionlogfile:
                    intrusionlogfile.write("SQL Injection(REGEX)❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act)+"\n")
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass

        first_line1=first_line.upper()
        for qw in zw:
            if qw in first_line1 :
                conn.send(failattemtmsg)
                conn.close()
                infoOut("[BLOCKED]SQL Injection",first_line,client_addr)
                with open('intrusion.log','a+') as intrusionlogfile:
                    intrusionlogfile.write("SQL Injection(REGEX)❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act))
                try:sys.exit(1)
                except SystemExit:sys.exit(1)
                except:pass
        
        sta=sta.replace(b'&frasl;',b'/')
        request=sta+act
    except SystemExit:sys.exit(1)
    except:
        trace("SQL Injection Check Failed !")
    #SQL Injection Check END

    #Intelligent Request Testing START (PENDING)
    try:
        if INTELLIGENT_REQ_TEST:
            #check act
            global zop
            if len(str(act))>3:
                try:
                    tu=str(act).split(" ")[1].split("?")[1]
                    intelliresult=zop.predict_sqli_attack(input_val=tu)
                    uui=True
                except:
                    uui=False
                if uui and intelliresult>INTELLIGENT_THRESHOLD[INELLIGENT_MODE.upper()]:
                    conn.send(failattemtmsg+b'i')
                    conn.close()
                    infoOut("[BLOCKED]Intelligent System Marked Request as SQL Injection",first_line,client_addr)
                    with open('intrusion.log','a+') as intrusionlogfile:
                        intrusionlogfile.write("SQL Injection(INTELLIGENT)❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act))
                    try:sys.exit(1)
                    except SystemExit:sys.exit(1)
                    except:pass
            #check firstline1
            if len(str(first_line1))>3:
                try:
                    tu=str(first_line1).split(" ")[1].split("?")[1]
                    intelliresult1=zop.predict_sqli_attack(input_val=tu)
                    uui=True
                except:
                    uui=False
                if uui and intelliresult1>INTELLIGENT_THRESHOLD[INELLIGENT_MODE.upper()]:
                    conn.send(failattemtmsg+b'i')
                    conn.close()
                    infoOut("[BLOCKED]Intelligent System Marked Request as SQL Injection",first_line,client_addr)
                    with open('intrusion.log','a+') as intrusionlogfile:
                        intrusionlogfile.write("SQL Injection(INTELLIGENT)❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act))
                    try:sys.exit(1)
                    except SystemExit:sys.exit(1)
                    except:pass
    except SystemExit:sys.exit(1)
    except:
        trace('Failed Intelligent Request Testing !')
    #Intelligent Request Testing END


    ###################################################
    ###############Apply WAF rules END#################
    ###################################################

    # LOGGING START
    try:
        if ipdetails['status']=='fail':z=""
        else:
            z=" Country : "+ipdetails['country']+" ("+ipdetails['regionName']+")"
            if ipdetails['proxy']=='true':z+=" [PROXY]"
        cadd=[]
        cadd.append(client_addr[0])
        cadd[0]+=z
        infoOut("Request",first_line,cadd)
    except:
        trace("Logging Failed !")
    # LOGGING END
    
    #Web Application address
    webserver = CURRENT_SERVER_HOST
    #Web Application port
    port = CURRENT_SERVER_PORT
    if port!=80:port1=":"+str(port)
    else:port1=''
    
    #replace WAF server with actual server in request
    try:
        second_line = request.split(b'\n')[1].split(b" ")[1][:-1]
        request=request.replace(second_line,(webserver+str(port1)).encode('utf-8'))
    except:
        trace("Could not replace server with actual server in request but, still trying to send!")
    
    #Inject True-Client-IP in headers
    try:
        if len(request.split(b'\n'))>1:
            zet=b'\r\n'+request[request.find(request.split(b'\n')[1]):]
        else:
            zet=''
        request=request.split(b'\n')[0][:-1]+b'\r\nTrue-Client-IP: '+(str(client_addr[0]).encode('utf-8'))+zet
    except:
        trace("Failed to Inject True-Client-IP")

    #WEB APPLICATION SOCKET
    try:
        # web application connection Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        s.connect((webserver, port))
        # send request
        s.send(request)
        
        while 1:
            # data from web application
            data = s.recv(MAX_RCV)
            
            if (len(data) > 0):
                # data revert back to client
                conn.send(data)
            else:
                break
        s.close()
        conn.close()
    except (socket.error):
        if s:s.close()
        if conn:conn.close()
        infoOut("Session Reset",first_line,client_addr)
        try:sys.exit(1)
        except SystemExit:sys.exit(1)
        except:pass
# working thread END

#function for rowfactory of sqlite fetch
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# thread : update rules from database
def dbthread(arg):
    profid=arg
    force=True
    if profid==None:
            profid=1
            force=False
    #creating connection to Sqlite3 Database
    try:
        conn = sqlite3.connect('waf.db')
        conn.row_factory = dict_factory
        while True:
            #updating profileID
            try:
                if not force:
                    c = conn.cursor()
                    c.execute("SELECT profID FROM CURPROF")
                    qres=c.fetchone()
                    c.close()
                    profid=qres['profID']
            except:
                traceback.print_exc()
                pass

            #updating server host and port
            try:
                c = conn.cursor()
                c.execute("SELECT host,port FROM CURSERV")
                qres=c.fetchone()
                c.close()
                global CURRENT_SERVER_HOST
                global CURRENT_SERVER_PORT
                CURRENT_SERVER_HOST=qres['host']
                CURRENT_SERVER_PORT=qres['port']
            except:
                traceback.print_exc()
                pass

            if profid==None:
                profid=1
            try:
                c = conn.cursor()
                c.execute("SELECT * FROM wafrules WHERE profID="+str(profid))
                qres=c.fetchall()
                c.close()
                if len(qres)<1:
                    raise Exception('No such Profile !')
                else:
                    profile=qres[0]
                #check for OnlyaAllowedIP flag
                if profile['onlyallowedip']==1:
                    global OnlyAllowedIP
                    if OnlyAllowedIP==False:
                        trace('Changed OnlyAllowedIP Flag to True')
                    global ALLOWED_CLIENTS
                    OnlyAllowedIP = True
                    #update ALLOWED_CLIENTS list as per profile
                    c = conn.cursor()
                    ALLOWED_CLIENTS=[]
                    c.execute("SELECT ip FROM ipclients WHERE status=1 AND profID="+str(profid))
                    qres=c.fetchall()
                    qer=[]
                    for  k in qres:qer.append(k['ip'])
                    ALLOWED_CLIENTS += qer
                    c.close()
                else:
                    if OnlyAllowedIP:
                        trace('Changed OnlyAllowedIP Flag to False')
                    OnlyAllowedIP = False
                #check for OnlyaAllowedCountry flag
                if profile['onlyallowedcountries']==1:
                    global OnlyAllowedCountries
                    if OnlyAllowedCountries==False:
                        trace('Changed OnlyAllowedCountries Flag to True')
                    global ALLOWED_COUNTRIES
                    OnlyAllowedCountries = True
                    #update ALLOWED_CLIENTS list as per profile
                    c = conn.cursor()
                    ALLOWED_COUNTRIES=[]
                    c.execute("SELECT countryCode FROM countryrule WHERE status=1 AND profID="+str(profid))
                    qres=c.fetchall()
                    qer=[]
                    for  k in qres:qer.append(k['countryCode'])
                    ALLOWED_COUNTRIES += qer
                    c.close()
                else:
                    if OnlyAllowedCountries:
                        trace('Changed OnlyAllowedCountries Flag to False')
                    OnlyAllowedCountries = False
                #check for Proxy Block flag
                if profile['proxyblock']==1:
                    global PROXY_BLOCK
                    if PROXY_BLOCK==False:
                        trace('Changed ProxyBlock Flag to True')
                    PROXY_BLOCK = True
                else:
                    if PROXY_BLOCK:
                        trace('Changed ProxyBlock Flag to False')
                    PROXY_BLOCK = False
                #check for intelligent test flag
                if profile['intelligenttest']==1:
                    global INTELLIGENT_REQ_TEST
                    if INTELLIGENT_REQ_TEST==False:
                        trace('Changed INTELLIGENT_REQ_TEST Flag to True')
                    INTELLIGENT_REQ_TEST = True
                else:
                    if INTELLIGENT_REQ_TEST:
                        trace('Changed INTELLIGENT_REQ_TEST Flag to False')
                    INTELLIGENT_REQ_TEST = False
                
                #set number of request to hold
                global REQUEST_HOLD
                REQUEST_HOLD = int(profile['requesthold'])

                #set Intelligent Mode
                global INELLIGENT_MODE
                if profile['intelligentmode']!="NULL":
                    INELLIGENT_MODE = profile['intelligentmode']

                #set max request size
                global MAX_RCV
                MAX_RCV = int(profile['maxrcv'])

                #check for BLOCKED CLIENTS
                global BLOCKED_CLIENTS
                c = conn.cursor()
                BLOCKED_CLIENTS=[]
                c.execute("SELECT ip FROM ipclients WHERE status=0 AND profID="+str(profid))
                qres=c.fetchall()
                qer=[]
                for  k in qres:qer.append(k['ip'])
                BLOCKED_CLIENTS += qer
                c.close()
                
                #check blocked Countries
                global BLOCKED_COUNTRY
                c = conn.cursor()
                BLOCKED_COUNTRY=[]
                c.execute("SELECT countryCode FROM countryrule WHERE status=0 AND profID="+str(profid))
                qres=c.fetchall()
                qer=[]
                for  k in qres:qer.append(k['countryCode'])
                BLOCKED_COUNTRY += qer
                c.close()
            except:
                profid=profid=(1,)
                traceback.print_exc()
                trace('No Such profile as'+str(profid)+"Using Default profile !")
            time.sleep(3)
        conn.commit()
        conn.close()
    except:
        print("Failed to connect to database, using in-file rules!")

#Output info if DEBUG true and color code as per rule hitted
def infoOut(rtyp,request,rfrom):
    if DEBUG:
        if "Request" == rtyp:clr = 34
        elif "[BLOCKED]IP Blacklist" in rtyp:clr = 33
        elif "[BLOCKED]SQL Injection" in rtyp: clr=31
        elif "[BLOCKED]Intelligent System Marked Request as SQL Injection" in rtyp:clr=31
        elif "[BLOCKED]PROXY IP" in rtyp: clr=32
        elif "[BLOCKED]Country Blocked" in rtyp: clr=32
        else:clr=30
        trace ("\033["+str(clr)+"m"+str(rfrom[0])+"\t"+str(rtyp)+"\t"+str(request)+"\033[0m")

#Output on DEBUG true
def trace(s):
    if DEBUG:
        print(s)

#main function defination
def main():
    #argument list length
    argl=len(sys.argv)

    if argl<2:
        port = 8080 #default Port
        if str(input("No arguements provided !\nEnter 'yes' if you want to continue with default configuration: ")).lower()!='yes':
            print("Usage: server.py portNO DEBUG/NODEBUG profileID")
            exit()
        trace ("No port arguement Now using port=8080")
    
    #set port given in argument
    if argl>1:
        #Check PORT
        try:
            port = int(sys.argv[1])
        except:
            print("Unknown arguemt at :",sys.argv[1])
            exit()
        if port<80:
            print("Given port is less than 80 : ",sys.argv[1],'\nProvide other port')
            exit()

    #set DEBUG if given in arguement   
    if argl>2:
        #Check DEBUG Flag
        if str(sys.argv[2]).upper()=="DEBUG":
            global DEBUG
            DEBUG=True
        else:
            print("Debug disabled as Second arguement provided is not DEBUG")
    
    #set profile for rules
    profileID = None
    if argl>3:
        try:
            profileID = (int(sys.argv[3]),)
        except:
            print('Invalid ProfileID given in argument',sys.argv[3])
            print('Using Default profile')

    # start thread to get updates from database
    try:
        thread.start_new_thread(dbthread,(profileID,))
    except SystemExit:sys.exit(1)
    except:
        print("Could not start thread for database Updates!\n#########Running on in-file rules !#########")

    host = ''
    print ("WAF Server Running on ",host,":",port)

    try:
        # create a socket
        global FIREWALL_HOST
        global FIREWALL_PORT
        FIREWALL_HOST=host
        FIREWALL_PORT=port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set address and port reuse
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to host and port
        s.bind((host, port))
        # start listening
        s.listen(REQUEST_HOLD)

    except socket.error as e:
        if s:
            s.close()
        trace ("Error while opening socket : "+ str(e))
        try:sys.exit(1)
        except SystemExit:sys.exit(1)
        except:pass

    # connections from client
    while True:
        conn, client_addr = s.accept()
        # request handling thread creation
        thread.start_new_thread(prthread, (conn, client_addr))
    s.close()
    
if __name__ == '__main__':
    try:
      main()
    except KeyboardInterrupt:
      sys.exit(0)
      pass
