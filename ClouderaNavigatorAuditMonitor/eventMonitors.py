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

def prepareUsername(user):
    loc = user.find('@')
    if loc > -1:
        return (user[:loc])
    else:
        return user

def prepareIP(ip):
    if str(ip).startswith('/'):
        return str(ip[1:])
    else:
        return str(ip)

def runMonitors(events):
    monitorResults = {}
    c = getCounters(events)
    hueUsers = hueCreateServiceUser(events)
    sentry = getSentryActions(events)
    ipMonitor = monitorIPSources(events)
    monitorResults['auth'] = c
    monitorResults['hue'] = hueUsers
    monitorResults['sentry'] = sentry
    monitorResults['unknownFailedIPs'] = ipMonitor
    print("Monitor Results")
    print(json.dumps(monitorResults,indent=4))
    return monitorResults

def monitorIPSources(events):
    UnknownIPSourceFailure = {}
    for host in events:
        ipSourceSuccess = {}
        ipSourceFailure = {}
        for event in events[host]:
            if 'username' in event.keys() and 'allowed' in event.keys() and 'ipAddress' in event.keys():
                user = prepareUsername(event['username'])
                ip = prepareIP(event['ipAddress'])
                #add username key and initialize list to both IP Source dicts, if not there already
                if user not in ipSourceSuccess.keys():
                    ipSourceSuccess[user] = []
                    ipSourceFailure[user] = []
                if event['allowed'] and ip not in ipSourceSuccess[user]:
                    ipSourceSuccess[user].append(ip)
                elif not event['allowed'] and ip not in ipSourceFailure[user]:
                    ipSourceFailure[user].append(ip)
        UnknownIPSourceFailure[host] = {}
        for foundUser in ipSourceSuccess.keys():
            for failedIP in ipSourceFailure[foundUser]:
                if failedIP not in ipSourceSuccess[foundUser]:
                    if foundUser not in UnknownIPSourceFailure[host].keys():
                        UnknownIPSourceFailure[host][foundUser] = []
                        UnknownIPSourceFailure[host][foundUser].append(failedIP)
                    else:
                        UnknownIPSourceFailure[host][foundUser].append(failedIP)
    return UnknownIPSourceFailure


def getCounters(events):
    authDict = {}
    authN = {}
    cmAuthN = {
        'success':{},
        'failure':{}
    }
    authZ = {}
    userFailures = {}
    for host in events:
        for event in events[host]:
            if ('username' in event.keys()) and ('command' in event.keys()) and ('allowed' in event.keys()):
                if event['command'] == 'authentication' and not event['allowed']:
                    key = prepareUsername(str(event['username'])) + event['ipAddress'] + str(event['allowed'])
                    if key in authN:
                        authN[key]['count'] += 1
                    else:
                        authN[key] = {}
                        authN[key]['count'] = 1
                        authN[key]['username'] = prepareUsername(str(event['username']))
                        authN[key]['command'] = event['command']
                        authN[key]['ipAddress'] = event['ipAddress']
                        authN[key]['allowed'] = str(event['allowed'])
                elif ('service' in event.keys()):
                    if (prepareUsername(str(event['username'])) in userFailures.keys()) and not event['allowed']:
                        userFailures[prepareUsername(str(event['username']))].append(event)
                    else:
                        if not event['allowed']:
                            userFailures[prepareUsername(str(event['username']))] = []
                            userFailures[prepareUsername(str(event['username']))].append(event)
                    key = prepareUsername(event['username']) + event['ipAddress'] + event['service'] + str(event['allowed'])
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
                    name = event['operationText'][(str(event['operationText']).find(':')+2):]
                    if name in cmAuthN['success'].keys():
                        cmAuthN['success'][name] = cmAuthN['success'][name] + 1
                    else:
                        cmAuthN['success'][name] = 1
        authDict[host] = {
            'Authentication':authN,
            'AuthorizationByUserandService':authZ,
            'Authorization Failures':userFailures,
            'ClouderaManagerAuthN':cmAuthN
        }
    return authDict

def hueCreateServiceUser(events):
    hueCreates = {}
    for host in events:
        createdUsers = []
        for event in events[host]:
            if (('username' in event.keys()) and ('service' in event.keys()) and ('command' in event.keys())):
                if ('hue' in str(event['service']).lower()) and (str(event['command']).lower() == 'create_user'):
                    createdUsers.append(event)
        hueCreates[host] = createdUsers
    return hueCreates

def getSentryActions(events):
    sentryByHost = {}
    for host in events:
        sentryActions = {}
        for event in events[host]:
            if ('service' in event.keys()):
                if ('sentry' in str(event['service']).lower()):
                    if str(event['ipAddress']).startswith('/'):
                        event['ipAddress'] = str(event['ipAddress'])[1:]
                    if (event['username'] in sentryActions.keys()):
                        sentryActions[str(event['username'])].append(event)
                    else:
                        sentryActions[str(event['username'])] = []
                        sentryActions[str(event['username'])].append(event)
        sentryByHost[host] = sentryActions
    return sentryByHost