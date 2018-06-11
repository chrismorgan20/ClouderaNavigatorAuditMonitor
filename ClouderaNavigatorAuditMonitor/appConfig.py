#   Copyright 2018 Christopher J. Morgan
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re
import json
import socket
import smtplib
import os
from cryptography.fernet import Fernet
from base64 import b64encode
from email.MIMEMultipart import MIMEMultipart


#Ask the user for configuration parameters
#Necessary Parameters: FQDNs of Cloudera Manager Hosts, CM Usernames, CM Passwords
#Construct dict dynamically for CM hosts, usernames and passwords 
#TODO:Make configuration generation into function called from command line without running CM config comparison
def getSetting(question,matchre,errortext):
    while True:
        setting = raw_input(question)
        if 'TRUE/FALSE' in matchre:
            if re.match('[YNyn]\Z',setting):
                return (setting.upper()).startswith("Y")
            else:
                print(errortext)
        else:
            if re.match(matchre,setting):
                return setting
            else:
                print(errortext)

def setMasterConfig():
    #Define empty dictionary to hold app master configuration
    masterconfig = {}
    hosts = getSetting("Input Cloudera Navigator host FQDNs or IP addresses, separated by commas if multiple: ", '[a-zA-Z0-9.,]*(?<=[a-zA-Z0-9])\Z', "Error: Please ensure Cloudera Navigator host FQDNs are properly formatted and separated by commas with no spaces.")
    cmhosts = hosts.split(",")
    cmhosts = [x.strip() for x in cmhosts]
    #generate encryption key from Cryptography package for use in encrypting passwords
    masterconfig['enckey']=Fernet.generate_key()
    f = Fernet(masterconfig['enckey'])
    #For each CM host, query for parameters, create nested dict for host which includes FQDN, username, and password
    masterconfig['cnfqdn'] = cmhosts
    for host in masterconfig['cnfqdn']:
        user = getSetting("Input Cloudera Navigator API username for " + host + ": ",'[a-zA-Z0-9.]*\Z',"Error: Please ensure username is alphanumeric. The only special characters allowed are periods.")
        passwd = raw_input("Enter password for Cloudera Navigator API user: ")
        apiport = getSetting("Enter port on which Navigator API runs: ",'[\d]*\Z',"Error: Please ensure port consists only of digits")
        if int(apiport)<1024:
            print("WARNING: Unusual port for API to be running on.")
        tls = getSetting("Use TLS to connect to API? (Y/N): ",'TRUE/FALSE',"Error: Please enter 'Y' or 'N'")
        #apiversion = getSetting("Enter API version number to use: ",'[\d]*\Z',"Error: Please enter valid API version number")
        moninterval = getSetting("Enter event extract interval in seconds: ",'[\d]*\Z',"Error: Please ensure interval consists only of digits")
        historicalEvents = getSetting("Get all historical events? (Y/N): ", 'TRUE/FALSE',"Error: Please enter 'Y' or 'N'")
        masterconfig[host] = {
            'user': user,
            'passwd': f.encrypt(passwd),
            'port': apiport,
			'tls': tls,
            'getHistory': historicalEvents,
            'lastExtract': False,
            'extInterval': int(moninterval),
            'analyzeOnlyExisting': False
            #'apiv': apiversion
        }
    analyzeLatest = getSetting("Always analyze only latest extract? (Y/N): ",'TRUE/FALSE',"Error: Please enter 'Y' or 'N'")
    masterconfig['analyzeOnlyLatest'] = analyzeLatest
    sendalerts = getSetting("Would you like to send monitor emails? (Y/N): ", 'TRUE/FALSE', "Error: Please enter 'Y' or 'N'")
    if sendalerts:
        smtpserver = getSetting("Input SMTP Server FQDN (or 'N' for no alerts: ",'[a-zA-Z0-9.]*\Z',"Error: Please ensure SMTP server FQDN is alphanumeric. The only special characters allowed are periods.")
        smtpport = getSetting("Enter SMTP Server Port: ",'[\d]*\Z',"Error: Please ensure port consists only of digits")
        commonsmtpports = [25, 465, 587]
        if int(smtpport) not in commonsmtpports:
            print("WARNING: Unusual SMTP port.")
        smtpuser = raw_input("Enter SMTP Server Username, or leave blank if unauthenticated: ")
        smtppass = ""
        if smtpuser:
            smtppass = raw_input("Enter SMTP Server password: ")
        smtptls = getSetting("Use TLS to connect to STMP Server? (Y/N): ",'TRUE/FALSE',"Error: Please enter 'Y' or 'N'")
        mailfrom = getSetting("Input Alert E-Mail 'FROM' Address: ",'[a-zA-Z0-9.@]*\Z',"Error: Please ensure from address is alphanumeric. The only special characters allowed are periods and @.")
        mailto = getSetting("Input Alert E-Mail 'TO' Addresses, separated by commas without spaces: ",'[a-zA-Z0-9,.@]*\Z',"Error: Please ensure To addresses are correct. The only special characters allowed are periods and @.")
        masterconfig['alerts'] = {
            'sendalerts': True,
            'smtpserver': smtpserver,
            'smtpport': smtpport,
            'smtpuser': smtpuser,
            'smtppass': f.encrypt(smtppass),
            'smtptls': smtptls,
            'emailfrom': mailfrom,
            'emailto': mailto.split(',')
        }
    else:
        masterconfig['alerts'] = {
            'sendalerts': False
        }
    with open("config.json",'w') as f:
        json.dump(masterconfig,f,indent=4)
    print(masterconfig)
    print("JSON")
    print(json.dumps(masterconfig, indent=4))

def getMasterConfig():
    with open("config.json",'r') as fc:
        masterconfg = json.loads(fc.read())
        return masterconfg

def createEmailHandler(alertconfig,enckey):
    f = Fernet(enckey)
    mailHandler = smtplib.SMTP(alertconfig['smtpserver'],int(alertconfig['smtpport']))
    if alertconfig['smtptls']:
        mailHandler.starttls()
    if alertconfig['smtpuser']:
        mailHandler.login(alertconfig['smtpuser'],f.decrypt(bytes(alertconfig['smtppass'])))
    message = MIMEMultipart()
    message['From'] = alertconfig['emailfrom']
    message['To'] = ','.join(alertconfig['emailto'])
    message['Subject'] = "Cloudera Security Report"
    return mailHandler,message