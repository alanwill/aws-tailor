# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
import os
import sys
import time

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
    requestId = incomingMessage['lambda']['requestId']
    requestorEmailAddress = incomingMessage['lambda']['requestorEmailAddress']
    emailContentText = incomingMessage['lambda']['emailContentText']
    emailContentHtml = incomingMessage['lambda']['emailContentHtml']

    # Update task status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "NOTIFY",
            "function": "talr-notify",
            "message": "-"
        }
    )

    # Look up the accountEmailAddress from the known requestId
    getAccountEmailAddress = accountInfo.query(
        IndexName='gsiRequestId',
        KeyConditionExpression=Key('requestId').eq(requestId)
    )
    accountEmailAddress = getAccountEmailAddress['Items'][0]['accountEmailAddress']

    # Look up account info
    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    requestorFullName = getAccountInfo['Item']['requestorFullName']
    accountTagLongProjectName = getAccountInfo['Item']['accountTagLongProjectName']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountSupportTeamEmail = getCbInfo['Item']['accountSupportTeamEmail']
    accountNotificationsFromEmail = getCbInfo['Item']['accountNotificationsFromEmail']

    sendNotification = ses.send_email(
        Source=accountNotificationsFromEmail,
        Destination={
            'ToAddresses': [
                requestorEmailAddress,
            ],
            'BccAddresses': [
                accountSupportTeamEmail,
            ]
        },
        Message={
            'Subject': {
                'Data': 'AWS Account Request',
                'Charset': 'UTF-8'
            },
            'Body': {
                'Text': {
                    'Data': emailContentText,
                    'Charset': 'UTF-8'
                },
                'Html': {
                    'Data': emailContentHtml,
                    'Charset': 'UTF-8'
                }
            }
        },
        ReplyToAddresses=[
            accountSupportTeamEmail,
        ]
    )

    print(sendNotification)

    # Update task status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "NOTIFY",
            "function": "talr-notify",
            "message": "-"
        }
    )
