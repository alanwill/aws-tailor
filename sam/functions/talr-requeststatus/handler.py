# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
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
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])

    try:
        print('path:requestId',
              re.match("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                       event['params']['path']['requestId']))
    except Exception as e:
        print(e)
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    if re.match("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                event['params']['path']['requestId']):

        requestId = event['params']['path']['requestId']

        # Lookup all task info
        getTaskStatus = taskStatus.query(
            KeyConditionExpression=Key('requestId').eq(requestId)
        )

        if getTaskStatus['Count'] == 0:
            raise Exception({"code": "4040", "message": "ERROR: Not found"})

        # Lookup email address for requestId
        getAccountEmailAddress = accountInfo.query(
            IndexName='gsiRequestId',
            KeyConditionExpression=Key('requestId').eq(requestId)
        )
        accountEmailAddress = getAccountEmailAddress['Items'][0]['accountEmailAddress']

        # Lookup accountInfo variables
        getAccountInfo = accountInfo.get_item(
            Key={
                'accountEmailAddress': accountEmailAddress
            }
        )

        # Try to populate the accountId if it's present.
        # It would typically not be present if talr-poll-cla hasn't run yet.
        try:
            accountId = getAccountInfo['Item']['accountId']
        except KeyError as e:
            print("no accountId present")
            print(e)
            accountId = "Unknown"

        accountName = getAccountInfo['Item']['accountTagLongProjectName']

        taskAccountCreation = 'in_progress'
        taskAccountValidation = 'in_progress'
        taskAccountAdDl = 'in_progress'
        taskAccountAdSecGroups = 'in_progress'
        taskIam = 'in_progress'
        taskCloudtrail = 'in_progress'
        taskConfig = 'in_progress'
        taskCloudability = 'in_progress'
        taskEnterpriseSupport = 'in_progress'
        taskVpc = 'in_progress'
        taskVpcFlowLogs = 'in_progress'
        taskVpcDns = 'in_progress'
        taskDirectconnect = 'in_progress'
        taskNotify = 'in_progress'

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'CLA_CREATION' and i['period'] == 'end':
                    taskAccountCreation = 'complete'
        except KeyError as e:
            print('Account creation not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'CLA_VALIDATION' and i['period'] == 'end':
                    taskAccountValidation = 'complete'
        except KeyError as e:
            print('Account validation not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'AD_DL' and i['period'] == 'end':
                    taskAccountAdDl = 'complete'
        except KeyError as e:
            print('AD DL not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'AD_SEC_GROUPS' and i['period'] == 'end':
                    taskAccountAdSecGroups = 'complete'
        except KeyError as e:
            print('AD Sec Groups not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'IAM' and i['period'] == 'end':
                    taskIam = 'complete'
        except KeyError as e:
            print('IAM not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'CLOUDTRAIL' and i['period'] == 'end':
                    taskCloudtrail = 'complete'
        except KeyError as e:
            print('Cloudtrail not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'CONFIG' and i['period'] == 'end':
                    taskConfig = 'complete'
        except KeyError as e:
            print('Config not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'ENTSUPPORT' and i['period'] == 'end':
                    taskEnterpriseSupport = 'complete'
        except KeyError as e:
            print('Enterprise Support not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'VPC' and i['period'] == 'end':
                    taskVpc = 'complete'
        except KeyError as e:
            print('VPC not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'VPCFLOWLOGS' and i['period'] == 'end':
                    taskVpcFlowLogs = 'complete'
        except KeyError as e:
            print('VPC Flow Logs not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'VPCDNS' and i['period'] == 'end':
                    taskVpcDns = 'complete'
        except KeyError as e:
            print('VPC DNS not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'CLOUDABILITY' and i['period'] == 'end':
                    taskCloudability = 'complete'
        except KeyError as e:
            print('Cloudability not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'DIRECTCONNECT' and i['period'] == 'end':
                    taskDirectconnect = 'complete'
        except KeyError as e:
            print('Direct Connect not yet complete')
            print(e)

        try:
            for i in getTaskStatus['Items']:
                if i['taskName'] == 'NOTIFY' and i['period'] == 'end':
                    taskNotify = 'complete'
        except KeyError as e:
            print('Notify not yet complete')
            print(e)

        # return output for new account creations
        for i in getTaskStatus['Items']:
            if "CLA_SUBMISSION" in i['taskName']:
                return {"status": taskNotify,
                        "accountName": accountName,
                        "accountId": accountId,
                        "taskStatus": {
                            "accountCreation": taskAccountCreation,
                            "accountValidation": taskAccountValidation,
                            "accountAdDl": taskAccountAdDl,
                            "accountAdSecGroups": taskAccountAdSecGroups,
                            "iam": taskIam,
                            "cloudtrail": taskCloudtrail,
                            "config": taskConfig,
                            "cloudability": taskCloudability,
                            "enterpriseSupport": taskEnterpriseSupport,
                            "vpc": taskVpc,
                            "vpcFlowLogs": taskVpcFlowLogs,
                            "vpcDns": taskVpcDns,
                            "directConnect": taskDirectconnect,
                            "notify": taskNotify
                        }
                        }

        # return output for account updates
        for i in getTaskStatus['Items']:
            if getTaskStatus['Count'] <= 2 and i['taskName'] == 'VPCFLOWLOGS':
                return {"status": taskVpcFlowLogs,
                        "accountName": accountName,
                        "accountId": accountId,
                        "taskStatus": {
                            "vpcFlowLogs": taskVpcFlowLogs
                        }
                        }
        # return output for account updates
        for i in getTaskStatus['Items']:
            if getTaskStatus['Count'] <= 2 and i['taskName'] == 'VPCDNS':
                return {"status": taskVpcDns,
                        "accountName": accountName,
                        "accountId": accountId,
                        "taskStatus": {
                            "vpcDns": taskVpcDns
                        }
                        }
        # return output for account updates
        for i in getTaskStatus['Items']:
            if getTaskStatus['Count'] <= 2 and i['taskName'] == 'CLOUDABILITY':
                return {"status": taskCloudability,
                        "accountName": accountName,
                        "accountId": accountId,
                        "taskStatus": {
                            "cloudability": taskCloudability
                        }
                        }
    else:
        print("Bad requestId was provided")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})
