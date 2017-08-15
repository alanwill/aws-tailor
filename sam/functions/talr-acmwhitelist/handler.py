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
    accountCbId = getCbInfo['Item']['accountCbId']
    accountSupportTeamEmail = getCbInfo['Item']['accountSupportTeamEmail']

    if accountTagEnvironment != 'tst':

        # Initialize credentials for linked account
        laCredentials = initialize_la_services(account_cb_id=accountCbId, la_account_id=laAccountId)

        # Initialize Support client with Linked Account credentials
        laSupport = boto3.client(
            'support',
            aws_access_key_id=laCredentials[0],
            aws_secret_access_key=laCredentials[1],
            aws_session_token=laCredentials[2],
            region_name='us-east-1'
        )

        # Create case in Payer Account requested Enterprise Support on Linked Account
        createCase = laSupport.create_case(
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


def initialize_la_services(account_cb_id, la_account_id):

    """
    :param account_cb_id: Account number of the consolidated billing (payer) account
    :param la_account_id: Account number of the Linked Account
    :return: access key, secret key and session token used to assume a session into the Linked Account.
    """

    # Payer account credentials
    payerAssumeRole = sts.assume_role(
        RoleArn="arn:aws:iam::" + account_cb_id + ":role/tailor",
        RoleSessionName="talrIamPayerAssumeRole"
    )
    payerCredentials = payerAssumeRole['Credentials']
    payer_aws_access_key_id = payerCredentials['AccessKeyId']
    payer_aws_secret_access_key = payerCredentials['SecretAccessKey']
    payer_aws_session_token = payerCredentials['SessionToken']

    # Linked account credentials
    laSts = boto3.client(
        'sts',
        aws_access_key_id=payer_aws_access_key_id,
        aws_secret_access_key=payer_aws_secret_access_key,
        aws_session_token=payer_aws_session_token,
    )

    laAssumeRole = laSts.assume_role(
        RoleArn="arn:aws:iam::" + la_account_id + ":role/PayerAccountAccessRole",
        RoleSessionName="talrIamLaAssumeRole"
    )
    laCredentials = laAssumeRole['Credentials']
    la_aws_access_key_id = laCredentials['AccessKeyId']
    la_aws_secret_access_key = laCredentials['SecretAccessKey']
    la_aws_session_token = laCredentials['SessionToken']

    return la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token
