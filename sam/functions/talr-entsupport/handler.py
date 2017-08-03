# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
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
sts = boto3.client('sts')


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
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "ENTSUPPORT",
            "function": "talr-entsupport",
            "message": incomingMessage
        }
    )

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCompanyName = getCbInfo['Item']['accountCompanyName']
    accountCbId = getCbInfo['Item']['accountCbId']
    accountSupportTeamEmail = getCbInfo['Item']['accountSupportTeamEmail']

    if accountTagEnvironment != 'tst':

        # Payer account credentials
        payerAssumeRole = sts.assume_role(
            RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
            RoleSessionName="talrEntsupportPayerAssumeRole"
        )
        payerCredentials = payerAssumeRole['Credentials']
        payer_aws_access_key_id = payerCredentials['AccessKeyId']
        payer_aws_secret_access_key = payerCredentials['SecretAccessKey']
        payer_aws_session_token = payerCredentials['SessionToken']

        # Linked account credentials
        paSupport = boto3.client(
            'support',
            aws_access_key_id=payer_aws_access_key_id,
            aws_secret_access_key=payer_aws_secret_access_key,
            aws_session_token=payer_aws_session_token,
        )

        # Create case in Payer Account requested Enterprise Support on Linked Account
        createCase = paSupport.create_case(
            subject='Enable Enterprise Support',
            serviceCode='account-management',
            severityCode='normal',
            categoryCode='billing',
            communicationBody='Please enable Enterprise Support on Linked Account: ' + laAccountId + '.',
            ccEmailAddresses=[
                accountSupportTeamEmail,
            ],
            language='en',
            issueType='customer-service'
        )
        print(createCase)

        # Update task end status
        updateStatus = taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "ENTSUPPORT",
                "function": "talr-entsupport",
                "message": incomingMessage
            }
        )

    else:
        print("No Enterprise Support enablement requested for", laAccountId)

        # Update task end status
        updateStatus = taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "ENTSUPPORT",
                "function": "talr-entsupport",
                "message": incomingMessage
            }
        )

    return
