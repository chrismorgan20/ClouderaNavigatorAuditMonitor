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

#Cloudera Navigator Audit

#import standard libraries
import smtplib
from email.MIMEText import MIMEText
import json
from datetime import datetime
import sys

#import third-party libraries
from pathlib import Path
import cm_api
import requests

#import custom local source
import eventMonitors
import appConfig
import eventQuery

#Check if prior app config exists, if not, enter setup mode
if not Path("config.json").is_file():
    print("App Configuration not found. Entering setup...")
    appConfig.setMasterConfig()
#Load Master Configuration
config = appConfig.getMasterConfig()

allEvents = eventQuery.getAllEvents(config)
monitors = eventMonitors.runMonitors(allEvents)

if config['alerts']['sendalerts']:
    print("Emailing event analysis results...")
    mail,msg = appConfig.createEmailHandler(config['alerts'],config['enckey'])
    msg.attach(MIMEText(json.dumps(monitors,indent=4), 'plain'))
    try:
        mail.sendmail(config['alerts']['emailfrom'],config['alerts']['emailto'],msg.as_string())
    except SMTPRecipientsRefused:
        print("ERROR: All Recipients refused by server")
    except SMTPHeloError:
        print("ERROR: SMTP Helo error")
    except SMTPSenderRefused:
        print("ERROR: SMTP Sender Refused by server")
    except SMTPDataError:
        print("ERROR: Unspecified SMTP Data Error")
    mail.quit()