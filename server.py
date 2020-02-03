import os
import sys
import socket
import time
import _thread as thread

DEBUG = False                # debug mode to see all debug messages
BLOCKED_CLIENTS = ['192.168.43.131']         # BLOCKED clients
REQUEST_HOLD = 50            # number connections to hold
MAX_RCV = 999999             # max number data bytes to receive

def prthread(conn, client_addr):
    # capture request from client
    request = conn.recv(MAX_RCV)
    result = request.find(b'\r\n\r\n')

    # parse the first line
    first_line = request.split(b'\n')[0]

    sta=request[:result+4]
    act=request[result+4:]

    #Apply WAF rules START
    failattemtmsg=b"\r\nHTTP/1.1 200 OK\r\n\r\nWeb Application Firewall Detected Suspecious activity !!\r\n"

     #special Character replace
    sp_char={'‘': '&lsquo;',"'":'&rsquo' ,'’': '&rsquo;', '‚': '&sbquo;','"': '&ldquo;', '“': '&ldquo;', '”': '&rdquo;', '„': '&bdquo;', '†': '&dagger;', '‡': '&Dagger;', '‰': '&permil;', '‹': '&lsaquo;', '›': '&rsaquo;', '♠': '&spades;', '♣': '&clubs;', '♥': '&hearts;', '♦': '&diams;', '‾': '&oline;', '←': '&larr;', '↑': '&uarr;', '→': '&rarr;', '↓': '&darr;', '↖': '&nwarr;', '↗': '&nearr;', '↙': '&swarr;', '↘': '&searr;', '™': '&trade;', '/': '&frasl;', '<': '&lt;', '>': '&gt;', '…': '&hellip;', '–': '&ndash;', '—': '&mdash;', '¡': '&iexcl;', '¢': '&cent;', '£': '&pound;', '¤': '&curren;', '¥': '&yen;', '¦': '&brvbar; or &brkbar;', '§': '&sect;', '¨': '&uml; or &die;', '©': '&copy;', 'ª': '&ordf;', '«': '&laquo;', '\xad': '&shy;', '®': '&reg;', '¯': '&macr; or &hibar;', '°': '&deg;', '±': '&plusmn;', '²': '&sup2;', '³': '&sup3;', '´': '&acute;', 'µ': '&micro;', '¶': '&para;', '·': '&middot;', '¸': '&cedil;', '¹': '&sup1;', 'º': '&ordm;', '»': '&raquo;', '¼': '&frac14;', '½': '&frac12;', '¾': '&frac34;', '¿': '&iquest;', 'À': '&Agrave;', 'Á': '&Aacute;', 'Â': '&Acirc;', 'Ã': '&Atilde;', 'Ä': '&Auml;', 'Å': '&Aring;', 'Æ': '&AElig;', 'Ç': '&Ccedil;', 'È': '&Egrave;', 'É': '&Eacute;', 'Ê': '&Ecirc;', 'Ë': '&Euml;', 'Ì': '&Igrave;', 'Í': '&Iacute;', 'Î': '&Icirc;', 'Ï': '&Iuml;', 'Ð': '&ETH;', 'Ñ': '&Ntilde;', 'Ò': '&Ograve;', 'Ó': '&Oacute;', 'Ô': '&Ocirc;', 'Õ': '&Otilde;', 'Ö': '&Ouml;', '×': '&times;', 'Ø': '&Oslash;', 'Ù': '&Ugrave;', 'Ú': '&Uacute;', 'Û': '&Ucirc;', 'Ü': '&Uuml;', 'Ý': '&Yacute;', 'Þ': '&THORN;', 'ß': '&szlig;', 'à': '&agrave;', 'á': '&aacute;', 'â': '&acirc;', 'ã': '&atilde;', 'ä': '&auml;', 'å': '&aring;', 'æ': '&aelig;', 'ç': '&ccedil;', 'è': '&egrave;', 'é': '&eacute;', 'ê': '&ecirc;', 'ë': '&euml;', 'ì': '&igrave;', 'í': '&iacute;', 'î': '&icirc;', 'ï': '&iuml;', 'ð': '&eth;', 'ñ': '&ntilde;', 'ò': '&ograve;', 'ó': '&oacute;', 'ô': '&ocirc;', 'õ': '&otilde;', 'ö': '&ouml;', '÷': '&divide;', 'ø': '&oslash;', 'ù': '&ugrave;', 'ú': '&uacute;', 'û': '&ucirc;', 'ü': '&uuml;', 'ý': '&yacute;', 'þ': '&thorn;', 'ÿ': '&yuml;', '∞': '&infin;'}
    for i in sp_char:
        act=act.replace(i.encode('utf-8'),sp_char[i].encode('utf-8'))
    
     #SQL Injection WAF Rules
    act1=act.upper()
    zw=[ b'%2BAND%28UNION', b'%2BAND%2BUNION%28', b'UNION%2BSELECT', b'||%2B%28SELECT', b'||%2BSUBSTR(', b'+AND+UNION', b'+AND+UNION(', b'UNION+SELECT', b'||+(SELECT', b'||+SUBSTR(' ,b' AND UNION', b' AND UNION(', b'UNION SELECT', b'|| (SELECT', b'|| SUBSTR(' ]
    for qw in zw:
        if qw in act1 :
            conn.send(failattemtmsg)
            conn.close()
            infoOut("SQL Injection",first_line,client_addr)
            open('intrusion.log','a+').write("SQL Injection❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act)+"\n")
            sys.exit(1)

    first_line1=first_line.upper()
    for qw in zw:
        if qw in first_line1 :
            conn.send(failattemtmsg)
            conn.close()
            infoOut("SQL Injection",first_line,client_addr)
            open('intrusion.log','a+').write("SQL Injection❡"+str(first_line)+"❡"+str(client_addr[0])+":"+str(client_addr[1])+"❡"+str(sta+act))
            sys.exit(1)
    
    sta=sta.replace(b'&frasl;',b'/')
    request=sta+act

    # check client BLOCKED_CLIENTS or not
    if client_addr[0] in BLOCKED_CLIENTS:
        infoOut("IP Blacklisted",first_line,client_addr)
        conn.send(b'\r\nHTTP/1.1 200 OK\r\n\r\nIP Blacklisted !!\r\n')
        conn.close()
        sys.exit(1)

    infoOut("Request",first_line,client_addr)
    webserver = "online.hnbgu.ac.in"
    port = 80
    if port!=80:port1=":"+str(port)
    else:port1=''
    try:
        second_line = request.split(b'\n')[1].split(b" ")[1][:-1]
        request=request.replace(second_line,(webserver+str(port1)).encode('utf-8'))
    except:
        pass
       

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
        sys.exit(1)

def infoOut(rtyp,request,rfrom):
    if DEBUG:
        if "IP Blacklist" in rtyp:clr = 33
        elif "Request" in rtyp:clr = 34
        elif "SQL Injection" in rtyp: clr=31
        else:clr=30
        print ("\033["+str(clr)+"m",rfrom[0],"\t",rtyp,"\t",request,"\033[0m")

def main():
    #check arguments
    if (len(sys.argv)<2):
        port = 8080 #default Port
        print ("No port arguement Now using port=8080")
    if (len(sys.argv)>1):
        #Check PORT
        port = int(sys.argv[1])
    if (len(sys.argv)==3):
        #Check DEBUG Flag
        if str(sys.argv[2]).upper()=="DEBUG":
            global DEBUG
            DEBUG=True
    host = ''
    print ("WAF Server Running on ",host,":",port)

    try:
        # create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to host and port
        s.bind((host, port))
        # start listening
        s.listen(REQUEST_HOLD)

    except socket.error as e:
        if s:
            s.close()
        print ("Error while opening socket : ", e)
        sys.exit(1)

    # connections from client
    while True:
        conn, client_addr = s.accept()
        # request handling thread creation
        thread.start_new_thread(prthread, (conn, client_addr))
    s.close()
    
if __name__ == '__main__':
    main()
