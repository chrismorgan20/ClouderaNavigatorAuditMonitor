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

def getAllHistoricalEvents(host,navfqdn,timenow,user,pw,interval):
    subtractIncrement = 604800000
    clouderaStart = getLinuxTimeUTCMillis(datetime(2008,1,1,0,0,0))
    ctime = timenow
    historicalEvents = []
    while ctime > clouderaStart: #Cloudera was founded in 2008, so get all events going back to 01/01/2008
        print("Get Historical events: " + str(ctime))
        reqevents = getEvents(host,navfqdn,"",(ctime-subtractIncrement),ctime,user,pw,interval)
        if reqevents:
            historicalEvents = historicalEvents + reqevents
        ctime = ctime - subtractIncrement
        print(ctime)
    return historicalEvents

def getEvents(host,navfqdn,query,startTime,endTime,user,pw,interval):
    allevents = {}
    allevents[host] = []
    interval = interval * 1000
    queryEnd = startTime + interval
    queryStart = startTime
    if queryEnd > endTime:
        queryEnd = endTime
    contQuery = True
    while(contQuery):
        events = {}
        events[host] = []
        moreEvents = True
        offset = 0
        while(moreEvents):
            print("getting events. Offset: " + str(offset))
            if navfqdn[:5] != 'https':
                #TODO: Add error catching and error sending email
                r = requests.get(str(navfqdn) + '/api/v3/audits?query=' + str(query) + '&startTime=' + str(queryStart) + '&endTime=' + str(queryEnd) + '&offset=' + str(int(10000 * offset)) + '&limit=10000',auth=(user,pw))
            else:
                #TODO: Get verify cert function to work correctly with custom CAs
                r = requests.get(str(navfqdn) + '/api/v3/audits?query=' + str(query) + '&startTime=' + str(queryStart) + '&endTime=' + str(queryEnd) + '&offset=' + str(int(10000 * offset)) + '&limit=10000',auth=(user,pw),verify=False)
            if (r.text != '[ ]'):
                events[host] = events[host] + (json.loads(r.text))
                offset = offset + 1
                print(r.text)
            else:
                moreEvents = False
                allevents[host] = allevents[host] + events[host]
            if events[host]:
                with open("./allevents/allevents_" + str(queryEnd) + ".json",'w') as fc:
                    json.dump(events,fc,indent=4)
        if queryEnd >= endTime:
            contQuery = False
        else:
            queryStart = queryEnd
            queryEnd = queryEnd + interval
            if queryEnd > endTime:
                queryEnd = endTime
    return allevents[host]

def mergeEvents(allEvents,currentEvents):
    for host in currentEvents.keys():
        if host not in allEvents.keys():
            allEvents[host] = currentEvents[host]
        else:
            allEvents[host] = allEvents[host] + currentEvents[host]
    return allEvents

def getAllEvents(config):
    subtractIncrement = 86400000 #static variable for value of 24 hours in milliseconds as increment to retrieve events by
    #initialize dictionary to hold all events
    allevents = {}
    if not Path("allevents").is_dir():
        os.makedirs("allevents")

    #load previous event extracts
    p = Path("./allevents/")
    if not config['analyzeOnlyLatest']:
        for x in p.iterdir():
            if not x.is_dir():
                with open(str(x),'r') as fr:
                    try:
                        allevents = mergeEvents(allevents,json.loads(fr.read()))
                    except:
                        print("ERROR: No Events could be loaded from file" + str(x))

    f = Fernet(bytes(config['enckey']))
    curTime = getLinuxTimeUTCNowMillis()
    for host in config['cnfqdn']:
        if not config[host]['analyzeOnlyExisting']:
            connectionstring = host + ":" + config[host]['port']
            if config[host]['tls']:
                connectionstring = 'https://' + connectionstring
            else:
                connectionstring = 'http://' + connectionstring
            #if first time running extract and getHistory option set, then call getAllHistoricalEvents
            if config[host]['getHistory'] and not config[host]['lastExtract'] and host not in allevents.keys():
                allevents[host] = getAllHistoricalEvents(host,connectionstring,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            elif host in allevents.keys() and not config[host]['lastExtract']:
                allevents[host] = allevents[host] + getEvents(host,connectionstring,"",curTime - subtractIncrement,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            elif host in allevents.keys():
                allevents[host] = allevents[host] + getEvents(host,connectionstring,"",config[host]['lastExtract'],curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            else:
                allevents[host] = getEvents(host,connectionstring,"",curTime - subtractIncrement,curTime,config[host]['user'],f.decrypt(bytes(config[host]['passwd'])),config[host]['extInterval'])
            config[host]['lastExtract'] = curTime
    with open("config.json",'w') as fcon:
        json.dump(config,fcon,indent=4)
    return allevents