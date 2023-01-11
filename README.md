# iWAF
Intelligent Web Application Firewall

## RUN

### In one terminal/cmd in `iWaf` directory
> pip3 install -r requirements.txt

> cd iwaf

> export FLASK_APP=wafDashboard

> flask run
(This starts dashboard for firewall profile and filter management) Username:Password :: WAFAdmin:DemoWAFuser

### In another terminal/cmd in `iWaf` directory
> cd iwaf

> python3 server.py {port any of choice} {DEBUG if required}
