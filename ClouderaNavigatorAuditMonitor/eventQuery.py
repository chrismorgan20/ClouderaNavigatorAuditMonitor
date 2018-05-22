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
import json
from datetime import datetime
import os

#import third-party libraries
from pathlib import Path
import cm_api
import requests
from cryptography.fernet import Fernet

def getLinuxTimeUTCNowMillis():
    return (int(((datetime.utcnow() - datetime(1970,1,1,0,0,0))).total_seconds())*1000)

def getLinuxTimeUTCMillis(desiredDateTime):
    return (int(((desiredDateTime - datetime(1970,1,1,0,0,0))).total_seconds())*1000)

def getAllHistoricalEvents(navfqdn,timenow,user,pw,interval):
    subtractIncrement = 604800000
    clouderaStart = getLinuxTimeUTCMillis(datetime(2008,1,1,0,0,0))
    ctime = timenow
    historicalEvents = []
    while ctime > clouderaStart: #Cloudera was founded in 2008, so get all events going back to 01/01/2008
        print("Get Historical events: " + str(ctime))
        reqevents = getEvents(navfqdn,"",(ctime-subtractIncrement),ctime,user,pw,interval)
        if reqevents:
            historicalEvents = historicalEvents + reqevents
        ctime = ctime - subtractIncrement
        print(ctime)
    return historicalEvents

def getEvents(navfqdn,query,startTime,endTime,user,pw,interval):
    allevents = []
    offset = 0
    moreEvents = True
    interval = interval * 1000
    queryEnd = startTime + interval
    limit = 20000
    if queryEnd > endTime:
        queryEnd = endTime
    contQuery = True
    while(contQuery):
        events = []
        while(moreEvents):
            print("getting events. Offset: " + str(offset))
            r = requests.get(str(navfqdn) + '/api/v3/audits?query=' + str(query) + '&startTime=' + str(startTime) + '&endTime=' + str(queryEnd) + '&offset=' + str(int(10000 * offset)) + '&limit=' + str(limit),auth=(user,pw))
            if (r.text != '[ ]'):
                events = events + (json.loads(r.text))
                offset = offset + 1
                print(r.text)
            else:
                moreEvents = False
                allevents = allevents + events
            if events:
                with open("./allevents/allevents_" + str(queryEnd) + ".json",'w') as fc:
                    json.dump(events,fc,indent=4)
        if queryEnd >= endTime:
            contQuery = False
        else:
            queryEnd = queryEnd + interval
            if queryEnd > endTime:
                queryEnd = endTime
    return allevents

def mergeEvents(allEvents,currentEvents):
    for host in currentEvents.keys():
        if host not in allEvents.keys():
            allEvents[host] = currentEvents[host]
        else:
            allEvents[host] = allEvents[host] + currentEvents[host]
    return allEvents

def getAllEvents(config,getOnlyExisting):
    subtractIncrement = 86400000 #static variable for value of 24 hours in milliseconds as increment to retrieve events by
    #initialize dictionary to hold all events
    allevents = {}
    if not Path("allevents").is_dir():
        os.makedirs("allevents")

    #load previous event extracts
    p = Path("./allevents/")
    for x in p.iterdir():
        if not x.is_dir():
            with open(str(x),'r') as fr:
                try:
                    allevents = mergeEvents(allevents,json.loads(fr.read()))
                except:
                    print("ERROR: No Events could be loaded from file" + x)
    
    #if not set to get only stored events
    if not getOnlyExisting:
        f = Fernet(bytes(config['enckey']))
        curTime = getLinuxTimeUTCNowMillis()
        for host in config['cnfqdn']:
            connectionstring = host + ":" + config[host]['port']
            if config[host]['tls']:
                connectionstring = 'https://' + connectionstring
            else:
                connectionstring = 'http://' + connectionstring
            #if first time running extract and getHistory option set, then call getAllHistoricalEvents
            if config[host]['getHistory'] and not config[host]['lastExtract'] and host not in allevents.keys():
                allevents[host] = getAllHistoricalEvents(connectionstring,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            elif host in allevents.keys() and not config[host]['lastExtract']:
                allevents[host] = allevents[host] + getEvents(connectionstring,"",curTime - subtractIncrement,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            elif host in allevents.keys():
                allevents[host] = allevents[host] + getEvents(connectionstring,"",config[host]['lastExtract'],curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            else:
                allevents[host] = getEvents(connectionstring,"",curTime - subtractIncrement,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            config[host]['lastExtract'] = curTime
        with open("config.json",'w') as fcon:
            json.dump(config,fcon,indent=4)
    return allevents