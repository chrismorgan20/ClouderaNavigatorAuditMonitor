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

import json

def runMonitors(events):
    c = getCounters(events)

    return c

def getCounters(events):
    authN = {}
    cmAuthN = {
        'success':{},
        'failure':{}
    }
    authZ = {}
    for host in events:
        for event in events[host]:
            #print("THIS IS AN EVENT")
            #print(event)
            if ('username' in event.keys()) and ('command' in event.keys()) and ('allowed' in event.keys()):
                if event['command'] == 'authentication':
                    key = event['username'] + event['ipAddress'] + str(event['allowed'])
                    if key in authN:
                        authN[key]['count'] += 1
                    else:
                        authN[key] = {}
                        authN[key]['count'] = 1
                        authN[key]['username'] = event['username'] 
                        authN[key]['command'] = event['command']
                        authN[key]['ipAddress'] = event['ipAddress']
                        authN[key]['allowed'] = str(event['allowed'])
                elif ('service' in event.keys()):
                    key = event['username'] + event['ipAddress'] + event['service'] + str(event['allowed'])
                    if key in authZ:
                        authZ[key]['count'] += 1
                    else:
                        authZ[key] = {}
                        authZ[key]['count'] = 1
                        authZ[key]['username'] = event['username'] 
                        authZ[key]['service'] = event['service']
                        authZ[key]['ipAddress'] = event['ipAddress']
                        authZ[key]['allowed'] = str(event['allowed'])
            if ('username' in event.keys()) and ('command' not in event.keys()) and ('operationText' in event.keys()) and ('serviceValues' in event.keys()) and ('allowed' in event.keys()):
                if str(event['operationText']).startswith("Successful login") and not event['serviceValues']:
                    name = event['operationText'][16:]
                    if name in cmAuthN['success'].keys():
                        cmAuthN['success'][name] = cmAuthN['success'][name] + 1
                    else:
                        cmAuthN['success'][name] = 1

    print("Authentication Counters")
    print(json.dumps(authN,indent=4))
    print("Authorization Counters")
    print(json.dumps(authZ,indent=4))
    print("Cloudera Manager Authentication")
    print(json.dumps(cmAuthN,indent=4))

def hueCreateServiceUser(events):
    createdUsers = []
    for event in events:
        if (('username' in event.keys()) and ('service' in event.keys()) and ('command' in event.keys())):
            if ('hue' in str(event['service']).lower()) and (str(event['command']).lower() == 'create_user'):
                createdUsers.append(event)

# NEXT EVENT TO BUILD DETECTION FOR
#    {
#        "username": "admin", 
#        "impersonator": "hue", 
#        "service": "hue", 
#        "timestamp": "2018-04-29T04:14:03.959Z", 
#        "command": "CREATE_USER", 
#        "allowed": true, 
#        "ipAddress": "192.168.1.95", 
#       "serviceValues": {
#            "url": "/useradmin/users/new", 
#            "operation_text": "Created User with username: hdfs", 
#            "service": "useradmin"
#        }
#    },