####################################################################
####################### Default Configuration START#################
####################################################################
FIREWALL_PORT = 8080
FIREWALL_HOST = ''
CURRENT_SERVER_HOST = "localhost" # Current application server host
CURRENT_SERVER_PORT = 80       # Current application port
ENVIRONMENT = 'PRODUCTION'     # Environment
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
INTELLIGENT_MODE = 'NORMAL'   # Intelligent mode
INTELLIGENT_THRESHOLD = {'NORMAL':.50,'HARD':0.481,'UNDER-ATTACK':.441} # Intelligent Threshold values as per modes
####################################################################
####################### Default Configuration END###################
####################################################################