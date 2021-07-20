#!/usr/bin/env python
# mythic2modrewrite.py

## Title:       mythic2modrewrite.py
## Author:      Joe Vest, Andrew Chiles

import argparse
import sys
import re
import json

description = '''
Python 3.0+
Converts Mythic (2.2.0+) profiles to Apache mod_rewrite .htaccess file format by using the User-Agent and URI Endpoint to create rewrite rules.
'''

parser = argparse.ArgumentParser(description=description)
parser.add_argument('-i', dest='inputfile', help='C2 Profile file', required=True)
parser.add_argument('-c', dest='c2server', help='C2 Server (http://teamserver)', required=True)
parser.add_argument('-r', dest='redirect', help='Redirect to this URL (http://google.com)', required=True)
parser.add_argument('-o', dest='out_file', help='Write .htaccess contents to target file', required=False)

args = parser.parse_args()

# Make sure we were provided with vaild URLs
# https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
regex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
    r'localhost|' #localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

if re.match(regex, args.c2server) is None:
    parser.print_help()
    print("[!] c2server is malformed. Are you sure {} is a valid URL?".format(args.c2server),file=sys.stderr)
    sys.exit(1)

if re.match(regex, args.redirect) is None:
    parser.print_help()
    print("[!] redirect is malformed. Are you sure {} is a valid URL?".format(args.redirect),file=sys.stderr)
    sys.exit(1)

# Read in the Mythic Payload Config
configFile = open(args.inputfile,"r")
contents = configFile.read()
contents = json.loads(contents)

# Errors
errorfound = False
errors = "\n##########\n[!] ERRORS\n"

# Make sure a C2 profile exists in the payload config before we continue
if "c2_profiles" in contents:
    c2profiles = contents["c2_profiles"]
else:
    print("[!] Could not find a c2profile in the provided JSON file",file=sys.stderr)
    sys.exit(1)

# Iterate over C2 profiles
# for profile in c2profiles:

# Pick the first item in the list of c2profiles
profile = c2profiles[0]["c2_profile_parameters"]

print("#### C2 Profile Details\n#{}\n".format(str(profile)))

# Get User-Agent
if "headers" in profile:
    for header in profile["headers"]:
        if header["name"] == "User-Agent":
            ua = header["value"]
else:
    ua = ''
    errors += "[!] User-Agent Not Found\n"
    errorfound = True

uris = []

# Get all profile URIs
if "get_uri" in profile:
    uris.append("/" + profile["get_uri"])
    # Remove any duplicate URIs
else:
    uris = ""
    errors += "[!] No GET URI found\n"
    errorfound = True

if "post_uri" in profile:
    uris.append("/" + profile["post_uri"])

else:
    uris = ""
    errors += "[!] No POST URI found\n"
    errorfound = True

# Create UA in modrewrite syntax. No regex needed in UA string matching, but () characters must be escaped
ua_string = ua.replace('(','\(').replace(')','\)')

# Create URI string in modrewrite syntax. "*" are needed in regex to support GET and uri-append parameters on the URI
uris_string = ".*|".join(uris) + ".*"


htaccess_template = '''
########################################
## .htaccess START
RewriteEngine On

## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Logic: If a requested URI AND the User-Agent matches, proxy the connection to the Teamserver
## Consider adding other HTTP checks to fine tune the check.  (HTTP Cookie, HTTP Referer, HTTP Query String, etc)
## Refer to http://httpd.apache.org/docs/current/mod/mod_rewrite.html
## Only allow GET and POST methods to pass to the C2 server
RewriteCond %{{REQUEST_METHOD}} ^(GET|POST) [NC]
## Profile URIs
RewriteCond %{{REQUEST_URI}} ^({uris})$
## Profile UserAgent
RewriteCond %{{HTTP_USER_AGENT}} "{ua}"
RewriteRule ^.*$ "{c2server}%{{REQUEST_URI}}" [P,L]

## Redirect all other traffic here
RewriteRule ^.*$ {redirect}/? [L,R=302]

## .htaccess END
########################################
'''
print("#### Save the following as .htaccess in the root web directory")
print("## Profile User-Agent Found:")
print("# {}".format(ua))
print("## Profile URIS Found ({}):".format(str(len(uris))))
for uri in uris:
    print("# {}".format(uri))

htaccess = htaccess_template.format(uris=uris_string, ua=ua_string, c2server=args.c2server, redirect=args.redirect)
if args.out_file:
    with open(args.out_file, 'w') as outfile:
        outfile.write(htaccess)
else:
    print(htaccess)

# Print Errors Found
if errorfound:
    print(errors, file=sys.stderr)
