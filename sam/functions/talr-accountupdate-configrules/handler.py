# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import uuid
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
awslambda = boto3.client('lambda')
sts = boto3.client('sts')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])

    try:
        print('context:resource-path', event['context']['resource-path'] == '/configrules')
        print('body-json:accountId', re.match("^[0-9]{12}$", event['body-json']['accountId']))
        print('header:accountCbAlias', event['params']['header']['accountCbAlias'])
    except Exception as e:
        print(e)
        print("regex not matching any values passed in request")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # VPC Flow Logs logic
    if event['context']['resource-path'] == '/configrules' and \
            re.match("^[0-9]{12}$", event['body-json']['accountId']) and \
            re.match("^[a-z-]{4,15}$", event['params']['header']['accountCbAlias']):

        requestId = str(uuid.uuid4())
        accountId = event['body-json']['accountId']
        accountCbAlias = event['params']['header']['accountCbAlias']
        functionAlias = event['stage-variables']['functionAlias']

        # Check if account already exists
        getAccountId = accountInfo.scan(
            ProjectionExpression='accountId, accountEmailAddress',
            FilterExpression=Attr('accountId').eq(accountId)
        )
        accountEmailAddress = getAccountId['Items'][0]['accountEmailAddress']

        if getAccountId['Count'] == 0:
            print("Account not found")
            raise Exception({"code": "4040", "message": "ERROR: Not found"})

        elif int(getAccountId['Count']) > 0:

            # Update accountInfo with new requestId
            updateAccountInfo = accountInfo.update_item(
                Key={
                    'accountEmailAddress': accountEmailAddress
                },
                UpdateExpression='SET #requestId = :val1',
                ExpressionAttributeNames={'#requestId': "requestId"},
                ExpressionAttributeValues={':val1': requestId}
            )

            # Lookup payer account number
            getCbInfo = cbInfo.get_item(
                Key={
                    'accountCbAlias': accountCbAlias
                }
            )
            accountCbId = getCbInfo['Item']['accountCbId']

            # Initialize credentials for linked account
            la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
                initialize_la_services(account_cb_id=accountCbId, la_account_id=accountId)

            # Build Lambda invoke payload
            message = "lambda={'requestId':'" + requestId + "', 'accountEmailAddress': '" + accountEmailAddress + "'}"
            payload = {"Records": [{"Sns": {"Message": message}}]}

            # Call Lambda
            invokeVpcFlowLogs = awslambda.invoke(
                FunctionName='talr-config',
                InvocationType='Event',
                Payload=json.dumps(payload),
                Qualifier=functionAlias
            )

            return {"code": "2020", "message": "Request Accepted", "requestId": requestId}

    else:
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})


def initialize_la_services(account_cb_id, la_account_id):
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

    # Initialize IAM client with Linked Account credentials
    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)