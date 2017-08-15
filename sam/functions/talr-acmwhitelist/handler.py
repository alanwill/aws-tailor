# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import os
import sys
import time
import boto3

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
sts = boto3.client('sts')
support = boto3.client('support')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
    accountEmailAddress = incomingMessage['lambda']['accountEmailAddress']

    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    laAccountId = getAccountInfo['Item']['accountId']
    requestId = getAccountInfo['Item']['requestId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "ACMWHITELIST",
            "function": "talr-acmwhitelist",
            "message": incomingMessage
        }
    )

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountDomainName = getCbInfo['Item']['accountDomainName']
    accountSupportTeamEmail = getCbInfo['Item']['accountSupportTeamEmail']

    if accountTagEnvironment != 'tst':

        # Create case in Payer Account requested Enterprise Support on Linked Account
        createCase = support.create_case(
            subject='Whitelist request',
            serviceCode='amazon-acm-service',
            severityCode='normal',
            categoryCode='domain-whitelisting',
            communicationBody='Please whitelist this account for cert requests to *.' + accountDomainName + '.',
            ccEmailAddresses=[
                accountSupportTeamEmail,
            ],
            language='en',
            issueType='technical'
        )
        print(createCase)

        # Update task end status
        taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "ACMWHITELIST",
                "function": "talr-acmwhitelist",
                "message": incomingMessage
            }
        )

    else:
        print("No ACM whitelisting requested for", laAccountId)

        # Update task end status
        taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "ACMWHITELIST",
                "function": "talr-acmwhitelist",
                "message": incomingMessage
            }
        )

    return
