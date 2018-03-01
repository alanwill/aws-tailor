# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys
import uuid
import time
import re

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    # If function is being pinged gracefully exit
    if not event:
        return

    requestId = str(uuid.uuid4())
    requestTime = str(time.time())
    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "REQUEST_VALIDATION",
            "function": "talr-receptionist",
            "message": "-"
        }
    )

    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    claRequestArn = os.environ['TAILOR_SNSARN_CLAREQUEST']

    try:
        # Test if the accountCbAlias key exists
        getCbInfo = cbInfo.get_item(
            Key={
                'accountCbAlias': event['body-json']['accountRequest']['accountCbAlias']
            }
        )

        # Test if the value of accountCbAlias is valid, it will be if cbInfo returns an entry.
        accountCbAlias = getCbInfo['Item']['accountCbAlias']

    except Exception as e:
        print(e)
        print("Improper accountCbAlias specified.")

        # Update task end status
        taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "REQUEST_VALIDATION",
                "function": "talr-receptionist",
                "message": "Bad Request"
            }
        )
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # Set variables from talr-cbInfo
    accountCbAlias = getCbInfo['Item']['accountCbAlias']
    accountEmailDomain = getCbInfo['Item']['accountEmailDomain']

    # Get list of valid environment names from talr-cbInfo
    accountEnvironmentList = list()
    for i in getCbInfo['Item']['accountEnvironments']:
        accountEnvironmentList.append(i)

    # Input validation
    testResults = {}
    accountCbAliasTest = True if "accountCbAlias" in event['body-json']['accountRequest'] and \
                                 event['body-json']['accountRequest']['accountCbAlias'] == accountCbAlias else False
    print("accountCbAliasTest is ", accountCbAliasTest)
    testResults['accountCbAliasTest'] = accountCbAliasTest
    accountRegulatedTest = True if "accountRegulated" in event['body-json']['accountRequest'] and \
                                   event['body-json']['accountRequest']['accountRegulated'] is True or \
                                   event['body-json']['accountRequest']['accountRegulated'] is False else False
    print("accountRegulatedTest is ", accountRegulatedTest)
    testResults['accountRegulatedTest'] = accountRegulatedTest
    accountVpcPrefixTest = True if "accountVpcPrefix" in event['body-json']['accountRequest'] and \
                                   re.search("^\/2([3-4]){1}$", event['body-json']['accountRequest']['accountVpcPrefix']) else False
    print("accountVpcPrefixTest is ", accountVpcPrefixTest)
    testResults['accountVpcPrefixTest'] = accountVpcPrefixTest
    accountVpcAzCountTest = True if "accountVpcAzCount" in event['body-json']['accountRequest'] and \
                                    event['body-json']['accountRequest']['accountVpcAzCount'] == "2" or \
                                    event['body-json']['accountRequest']['accountVpcAzCount'] == "3" else False
    print("accountVpcAzCountTest is ", accountVpcAzCountTest)
    testResults['accountVpcAzCountTest'] = accountVpcAzCountTest
    accountRegionTest = True if "accountRegion" in event['body-json']['accountRequest'] and \
                                "us-east-1" in event['body-json']['accountRequest']['accountRegion'] or \
                                "us-west-2" in event['body-json']['accountRequest']['accountRegion'] else False
    print("accountRegionTest is ", accountRegionTest)
    testResults['accountRegionTest'] = accountRegionTest
    accountTagCostCenterTest = True if "accountTagCostCenter" in event['body-json']['accountRequest'] and \
                                       re.search("^\d{10}", event['body-json']['accountRequest']['accountTagCostCenter']) \
        else False
    print("accountTagCostCenterTest is ", accountTagCostCenterTest)
    testResults['accountTagCostCenterTest'] = accountTagCostCenterTest
    accountTagLongProjectNameTest = True if "accountTagLongProjectName" in event['body-json']['accountRequest'] and \
                                            re.search("^(\D|\d){3,50}$",
                                                      event['body-json']['accountRequest']['accountTagLongProjectName']) else False
    print("accountTagLongProjectNameTest is ", accountTagLongProjectNameTest)
    testResults['accountTagLongProjectNameTest'] = accountTagLongProjectNameTest
    accountTagShortProjectNameTest = True if "accountTagShortProjectName" in event['body-json']['accountRequest'] and \
                                             re.search("^[a-z0-9]{2,15}$",
                                                       event['body-json']['accountRequest']['accountTagShortProjectName']) else False
    print("accountTagShortProjectNameTest is ", accountTagShortProjectNameTest)
    testResults['accountTagShortProjectNameTest'] = accountTagShortProjectNameTest
    accountTagEnvironmentTest = True if "accountTagEnvironment" in event['body-json']['accountRequest'] and \
                                        event['body-json']['accountRequest']['accountTagEnvironment'] in \
                                        accountEnvironmentList else False
    print("accountTagEnvironmentTest is ", accountTagEnvironmentTest)
    testResults['accountTagEnvironmentTest'] = accountTagEnvironmentTest
    accountUserAccessListTest = True if "accountUserAccessList" in event['body-json']['accountRequest'] and \
                                        re.search("^(\[.*?\])", str(event['body-json']['accountRequest']['accountUserAccessList'])) \
        else False
    print("accountUserAccessListTest is ", accountUserAccessListTest)
    testResults['accountUserAccessListTest'] = accountUserAccessListTest
    accountTechnicalContactFullNameTest = True if "accountTechnicalContactFullName" in event['body-json']['accountRequest'] and \
                                                  re.search("^([a-zA-Z0-9_-]| |[a-zA-Z0-9_-]){3,50}$",
                                                            event['body-json']['accountRequest']['accountTechnicalContactFullName']) \
        else False
    print("accountTechnicalContactFullNameTest is ", accountTechnicalContactFullNameTest)
    testResults['accountTechnicalContactFullNameTest'] = accountTechnicalContactFullNameTest
    accountTechnicalContactUsernameTest = True if "accountTechnicalContactUsername" in event['body-json']['accountRequest'] and \
                                                  re.search("^([a-z_]){3,20}$",
                                                            event['body-json']['accountRequest']['accountTechnicalContactUsername']) \
        else False
    print("accountTechnicalContactUsernameTest is ", accountTechnicalContactUsernameTest)
    testResults['accountTechnicalContactUsernameTest'] = accountTechnicalContactUsernameTest
    requestorFullNameTest = True if "requestorFullName" in event['body-json']['accountRequest'] and \
                                    re.search("^(\w| |\w){3,50}$", event['body-json']['accountRequest']['requestorFullName']) \
        else False
    print("requestorFullNameTest is ", requestorFullNameTest)
    testResults['requestorFullNameTest'] = requestorFullNameTest
    requestorUsernameTest = True if "requestorUsername" in event['body-json']['accountRequest'] and \
                                    re.search("^([a-z_]){3,20}$", event['body-json']['accountRequest']['requestorUsername']) \
        else False
    print("requestorUsernameTest is ", requestorUsernameTest)
    testResults['requestorUsernameTest'] = requestorUsernameTest
    requestorManagerTest = True if "requestorManager" in event['body-json']['accountRequest'] and \
                                   re.search("^([a-zA-Z0-9_-]| |[a-zA-Z0-9_-]){3,50}$", event['body-json']['accountRequest']['requestorManager']) \
        else False
    print("requestorManagerTest is ", requestorManagerTest)
    testResults['requestorManagerTest'] = requestorManagerTest
    requestorDepartmentTest = True if "requestorDepartment" in event['body-json']['accountRequest'] and \
                                      re.search("^(\w| |\w|-|){3,100}$", event['body-json']['accountRequest']['requestorDepartment']) \
        else False
    print("requestorDepartmentTest is ", requestorDepartmentTest)
    testResults['requestorDepartmentTest'] = requestorDepartmentTest
    requestorEmailAddressTest = True if "requestorEmailAddress" in event['body-json']['accountRequest'] and \
                                        re.search("^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$",
                                                  event['body-json']['accountRequest']['requestorEmailAddress'].lower()) else False
    print("requestorEmailAddressTest is ", requestorEmailAddressTest)
    testResults['requestorEmailAddressTest'] = requestorEmailAddressTest
    externalTransactionIdTest = True if "externalTransactionId" in event['body-json']['accountRequest'] and \
                                        re.search("^(\D|\d){0,500}$",
                                                  event['body-json']['accountRequest']['externalTransactionId']) else False
    print("externalTransactionIdTest is ", externalTransactionIdTest)
    testResults['externalTransactionIdTest'] = externalTransactionIdTest
    commentTest = True if "comment" in event['body-json']['accountRequest'] and \
                          re.search("^(\D|\d){0,200}$", event['body-json']['accountRequest']['comment']) else False

    print("commentTest is ", commentTest)
    testResults['commentTest'] = commentTest

    # Check if externalTransactionId is blank
    if len(event['body-json']['accountRequest']['externalTransactionId']) == 0:
        externalTransactionId = "-"
    else:
        externalTransactionId = event['body-json']['accountRequest']['externalTransactionId']

    # Check if comment is blank
    if len(event['body-json']['accountRequest']['comment']) == 0:
        comment = "-"
    else:
        comment = event['body-json']['accountRequest']['comment']

    # Validate that all tests passed otherwise return error
    for test, result in testResults.items():
        if result is False:
            raise Exception({"code": "4000", "message": "Failed " + test})

    # Event input variable assignment
    accountCbAlias = event['body-json']['accountRequest']['accountCbAlias']
    accountRegulated = event['body-json']['accountRequest']['accountRegulated']
    accountVpcPrefix = event['body-json']['accountRequest']['accountVpcPrefix']
    accountVpcAzCount = event['body-json']['accountRequest']['accountVpcAzCount']
    accountRegion = event['body-json']['accountRequest']['accountRegion']
    accountTagCostCenter = event['body-json']['accountRequest']['accountTagCostCenter']
    accountTagLongProjectName = event['body-json']['accountRequest']['accountTagLongProjectName'].lower()
    accountTagShortProjectName = event['body-json']['accountRequest']['accountTagShortProjectName'].lower()
    accountTagEnvironment = event['body-json']['accountRequest']['accountTagEnvironment']
    accountUserAccessList = event['body-json']['accountRequest']['accountUserAccessList']
    accountTechnicalContactFullName = event['body-json']['accountRequest']['accountTechnicalContactFullName']
    accountTechnicalContactUsername = event['body-json']['accountRequest']['accountTechnicalContactUsername']
    requestorFullName = event['body-json']['accountRequest']['requestorFullName']
    requestorUsername = event['body-json']['accountRequest']['requestorUsername']
    requestorManager = event['body-json']['accountRequest']['requestorManager']
    requestorDepartment = event['body-json']['accountRequest']['requestorDepartment']
    requestorEmailAddress = event['body-json']['accountRequest']['requestorEmailAddress'].lower()

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )

    accountTaskSuccessCount = getCbInfo['Item']['accountTaskSuccessCount']
    accountEmailAddress = "aws." + getCbInfo['Item']['accountDivision'].lower() + "." + \
                          accountTagShortProjectName + "." + accountTagEnvironment + \
                          "@" + accountEmailDomain

    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )

    # Check if this request causes a duplicate entry, if yes, return error
    if "Item" in getAccountInfo:
        # Update task end status
        taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "REQUEST_VALIDATION",
                "function": "talr-receptionist",
                "message": "Duplicate Request"
            }
        )
        raise Exception({"code": "4090", "message": "Duplicate request"})

    # Insert fields into DynamoDB
    accountInfo.put_item(
        Item={
            'requestId': requestId,
            'requestTime': requestTime,
            'accountStatus': 'ACTIVE',
            'accountEmailAddress': accountEmailAddress,
            'accountCbAlias': accountCbAlias,
            'accountRegulated': accountRegulated,
            'accountVpcAzCount': accountVpcAzCount,
            'accountVpcPrefix': accountVpcPrefix,
            'accountRegion': accountRegion,
            'accountTagCostCenter': accountTagCostCenter,
            'accountTagLongProjectName': accountTagLongProjectName,
            'accountTagShortProjectName': accountTagShortProjectName,
            'accountTagEnvironment': accountTagEnvironment,
            'accountUserAccessList': accountUserAccessList,
            'accountTechnicalContactFullName': accountTechnicalContactFullName,
            'accountTechnicalContactUsername': accountTechnicalContactUsername,
            'requestorFullName': requestorFullName,
            'requestorUsername': requestorUsername,
            'requestorManager': requestorManager,
            'requestorDepartment': requestorDepartment,
            'requestorEmailAddress': requestorEmailAddress,
            'externalTransactionId': externalTransactionId,
            'comment': comment,
            'accountVpcCidr': {}
        }
    )

    # Print requestId to help troubleshooting if SNS publish fails
    print(requestId)

    sns.publish(
        TopicArn=claRequestArn,
        Message='{ "default" : { "requestId": "' + requestId + '", "accountEmailAddress": "' + accountEmailAddress +
                '", "accountTagLongProjectName": "' + accountTagLongProjectName + '", "accountCbAlias": "' +
                accountCbAlias + '" }, "lambda" : { "requestId": "' + requestId + '", "accountEmailAddress": "' +
                accountEmailAddress + '", "accountTagLongProjectName": "' + accountTagLongProjectName +
                '", "accountCbAlias": "' + accountCbAlias + '" }}'
    )

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "REQUEST_VALIDATION",
            "function": "talr-receptionist",
            "message": {"accountTaskSuccessCount": accountTaskSuccessCount}
        }
    )

    return {"code": "2020", "message": "Request Accepted", "requestId": requestId}
