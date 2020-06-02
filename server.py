import sys
import socket
import _thread as thread
import requests
import json

####################################################################
####################### Default Configuration START#################
####################################################################

DEBUG = True                 # debug mode to see all debug messages
OnlyAllowedIP = False        # Check for only allowed clients rule
ALLOWED_CLIENTS = []         # Allowed Clients
BLOCKED_CLIENTS = ['192.168.43.2']         # BLOCKED clients
REQUEST_HOLD = 50            # number connections to hold
MAX_RCV = 999999             # max number data bytes to receive
PROXY_BLOCK = True           # Block access through known Web Proxy or VPN
INTELLIGENT_REQ_TEST = False # Intelligent request testing via Machine Learning (Increases Response time!)
BLOCKED_COUNTRY = ['IN']     # Blocked Access in specific countries via IP geo location

####################################################################
####################### Default Configuration END###################
####################################################################

Special_Chars_HTML_code={ '"':"&quot;","'":"&apos;","&":"&amp;","<":"&lt;",">":"&gt;","Œ":"&OElig;","œ":"&oelig;","Š":"&Scaron;","š":"&scaron;","Ÿ":"&Yuml;","ƒ":"&fnof;","ˆ":"&circ;","˜":"&tilde;"," ":"&ensp;"," ":"&emsp;"," ":"&thinsp;","‌":"&zwnj;","‍":"&zwj;","‎":"&lrm;","‏":"&rlm;","–":"&ndash;","—":"&mdash;","‘":"&lsquo;","’":"&rsquo;","‚":"&sbquo;","“":"&ldquo;","”":"&rdquo;","„":"&bdquo;","†":"&dagger;","‡":"&Dagger;","•":"&bull;","…":"&hellip;","‰":"&permil;","′":"&prime;","″":"&Prime;","‹":"&lsaquo;","›":"&rsaquo;","‾":"&oline;","€":"&euro;","™":"&trade;","←":"&larr;","↑":"&uarr;","→":"&rarr;","↓":"&darr;","↔":"&harr;","↵":"&crarr;","⌈":"&lceil;","⌉":"&rceil;","⌊":"&lfloor;","⌋":"&rfloor;","◊":"&loz;","♠":"&spades;","♣":"&clubs;","♥":"&hearts;","♦":"&diams;","∀":"&forall;","∂":"&part;","∃":"&exist;","∅":"&empty;","∇":"&nabla;","∈":"&isin;","∉":"&notin;","∋":"&ni;","∏":"&prod;","∑":"&sum;","−":"&minus;","∗":"&lowast;","√":"&radic;","∝":"&prop;","∞":"&infin;","∠":"&ang;","∧":"&and;","∨":"&or;","∩":"&cap;","∪":"&cup;","∫":"&int;","∴":"&there4;","∼":"&sim;","≅":"&cong;","≈":"&asymp;","≠":"&ne;","≡":"&equiv;","≤":"&le;","≥":"&ge;","⊂":"&sub;","⊃":"&sup;","⊄":"&nsub;","⊆":"&sube;","⊇":"&supe;","⊕":"&oplus;","⊗":"&otimes;","⊥":"&perp;","⋅":"&sdot;","Α":"&Alpha;","Β":"&Beta;","Γ":"&Gamma;","Δ":"&Delta;","Ε":"&Epsilon;","Ζ":"&Zeta;","Η":"&Eta;","Θ":"&Theta;","Ι":"&Iota;","Κ":"&Kappa;","Λ":"&Lambda;","Μ":"&Mu;","Ν":"&Nu;","Ξ":"&Xi;","Ο":"&Omicron;","Π":"&Pi;","Ρ":"&Rho;","Σ":"&Sigma;","Τ":"&Tau;","Υ":"&Upsilon;","Φ":"&Phi;","Χ":"&Chi;","Ψ":"&Psi;","Ω":"&Omega;","α":"&alpha;","β":"&beta;","γ":"&gamma;","δ":"&delta;","ε":"&epsilon;","ζ":"&zeta;","η":"&eta;","θ":"&theta;","ι":"&iota;","κ":"&kappa;","λ":"&lambda;","μ":"&mu;","ν":"&nu;","ξ":"&xi;","ο":"&omicron;","π":"&pi;","ρ":"&rho;","ς":"&sigmaf;","σ":"&sigma;","τ":"&tau;","υ":"&upsilon;","φ":"&phi;","χ":"&chi;","ψ":"&psi;","ω":"&omega;","ϑ":"&thetasym;","ϒ":"&upsih;","ϖ":"&piv;","À":"&Agrave;","Á":"&Aacute;","Â":"&Acirc;","Ã":"&Atilde;","Ä":"&Auml;","Å":"&Aring;","Æ":"&AElig;","Ç":"&Ccedil;","È":"&Egrave;","É":"&Eacute;","Ê":"&Ecirc;","Ë":"&Euml;","Ì":"&Igrave;","Í":"&Iacute;","Î":"&Icirc;","Ï":"&Iuml;","Ð":"&ETH;","Ñ":"&Ntilde;","Ò":"&Ograve;","Ó":"&Oacute;","Ô":"&Ocirc;","Õ":"&Otilde;","Ö":"&Ouml;","Ø":"&Oslash;","Ù":"&Ugrave;","Ú":"&Uacute;","Û":"&Ucirc;","Ü":"&Uuml;","Ý":"&Yacute;","Þ":"&THORN;","ß":"&szlig;","à":"&agrave;","á":"&aacute;","â":"&acirc;","ã":"&atilde;","ä":"&auml;","å":"&aring;","æ":"&aelig;","è":"&egrave;","é":"&eacute;","ê":"&ecirc;","ë":"&euml;","ì":"&igrave;","í":"&iacute;","î":"&icirc;","ï":"&iuml;","ð":"&eth;","ñ":"&ntilde;","ò":"&ograve;","ó":"&oacute;","ô":"&ocirc;","õ":"&otilde;","ö":"&ouml;","ø":"&oslash;","ù":"&ugrave;","ú":"&uacute;","û":"&ucirc;","ü":"&uuml;","ý":"&yacute;","þ":"&thorn;","ÿ":"&yuml;","¡":"&iexcl;","¢":"&cent;","¥":"&yen;","§":"&sect;","©":"&copy;","ª":"&ordf;","«":"&laquo;","¬":"&not;","®":"&reg;","¯":"&macr;","°":"&deg;","±":"&plusmn;","²":"&sup2;","³":"&sup3;","´":"&acute;","µ":"&micro;","¶":"&para;","·":"&middot;","¸":"&cedil;","¹":"&sup1;","º":"&ordm;","»":"&raquo;","¼":"&frac14;","½":"&frac12;","¾":"&frac34;","¿":"&iquest;","×":"&times;","÷":"&divide;"}
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

#working thread
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

    # parse the first line
    first_line = request.split(b'\n')[0]

    sta=request[:result+4]
    act=request[result+4:]

    failattemtmsg=b"\r\nHTTP/1.1 200 OK\r\n\r\n<h1>Web Application Firewall Detected Suspecious activity !!</h1>\r\n"
    
    ###################################################
    ###############Apply WAF rules START###############
    ###################################################

    # check Country Blocking START
    try:
        if ipdetails['countryCode'] in BLOCKED_COUNTRY:
            infoOut("[BLOCKED]Country Blocked("+ipdetails['country']+")",first_line,client_addr)
            conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service is not available in your country !!</h1>\r\n')
            conn.close()
            try:sys.exit(1)
            except:pass
    except:
        print("Country check Failed !")
    # check Country Blocking END

    # check PROXY IPs START
    try:
        if ipdetails['proxy']=='true' and PROXY_BLOCK:
            infoOut("[BLOCKED]PROXY IP",first_line,client_addr)
            conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>This service can not be used with proxy !!</h1>\r\n')
            conn.close()
            try:sys.exit(1)
            except:pass
    except:
        print("Proxy IP check Failed !")
    # check PROXY IPs END

    # IP Based Filtering START
    try:
        if OnlyAllowedIP:
            if client_addr[0] not in ALLOWED_CLIENTS:
                infoOut("[BLOCKED]IP Blacklisted",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>IP Blacklisted !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except:pass
        else:
            if client_addr[0] in BLOCKED_CLIENTS:
                infoOut("[BLOCKED]IP Blacklisted",first_line,client_addr)
                conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\n<h1>IP Blacklisted !!</h1>\r\n')
                conn.close()
                try:sys.exit(1)
                except:pass
    except:
        print("IP Based Filtering Failed !")
    # IP Based Filtering END

    #special Character Sanitisation START
    try:
        for key, value in Special_Chars_HTML_code.items():
            act=act.replace(key.encode('utf-8'),value.encode('utf-8'))
    except:
        print("Special Character Sanitization Failed !")
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
                    intrusionlogfile.write("SQL Injection❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act)+"\n")
                try:sys.exit(1)
                except:pass

        first_line1=first_line.upper()
        for qw in zw:
            if qw in first_line1 :
                conn.send(failattemtmsg)
                conn.close()
                infoOut("[BLOCKED]SQL Injection",first_line,client_addr)
                with open('intrusion.log','a+') as intrusionlogfile:
                    intrusionlogfile.write("SQL Injection❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act))
                try:sys.exit(1)
                except:pass
        
        sta=sta.replace(b'&frasl;',b'/')
        request=sta+act
    except:
        print("SQL Injection Check Failed !")
    #SQL Injection Check END

    #Intelligent Request Testing START (PENDING)
    try:
        if INTELLIGENT_REQ_TEST:
            ##pass request to machine learning model for testing
            pass
    except:
        print('Failed Intelligent Request Testing !')
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
        print("Logging Failed !")
    # LOGGING END
    
    #Web Application address
    webserver = "online.hnbgu.ac.in"
    #Web Application port
    port = 80
    if port!=80:port1=":"+str(port)
    else:port1=''
    try:
        second_line = request.split(b'\n')[1].split(b" ")[1][:-1]
        request=request.replace(second_line,(webserver+str(port1)).encode('utf-8'))
    except:
        pass

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
        except:pass

#Output info if DEBUG true and color code as per rule hitted
def infoOut(rtyp,request,rfrom):
    if DEBUG:
        if "Request" in rtyp:clr = 34
        elif "[BLOCKED]IP Blacklist" in rtyp:clr = 33
        elif "[BLOCKED]SQL Injection" in rtyp: clr=31
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
    
    host = ''
    print ("WAF Server Running on ",host,":",port)

    try:
        # create a socket
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
