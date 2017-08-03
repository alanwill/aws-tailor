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
sns = boto3.client('sns')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    dispatchRequestArn = os.environ['TAILOR_SNSARN_DISPATCH_REQUEST']
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])

    try:
        if incomingMessage['info'] == "LinkedAccountCreationStarted":
            getAccountInfo = accountInfo.get_item(
                Key={
                    'accountEmailAddress': incomingMessage['email']
                }
            )
            requestId = getAccountInfo['Item']['requestId']

            # Update task start status
            updateStatus = taskStatus.put_item(
                Item={
                    "requestId": requestId,
                    "eventTimestamp": str(time.time()),
                    "period": "start",
                    "taskName": "CLA_CREATION",
                    "function": "talr-director",
                    "message": incomingMessage
                }
            )
            return
    except KeyError:
        pass

    # Look up email address and other account fields in accountInfo table
    accountEmailAddress = incomingMessage['linkedAccountEmail']
    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    requestId = getAccountInfo['Item']['requestId']
    accountTagShortProjectName = getAccountInfo['Item']['accountTagShortProjectName']
    accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']

    # Look up account division
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountDivision = getCbInfo['Item']['accountDivision'].lower()
    accountCompanyCode = getCbInfo['Item']['accountCompanyCode']
    accountCbId = getCbInfo['Item']['accountCbId']

    if "linkedAccountId" in incomingMessage and getAccountInfo['Item']['accountEmailAddress'] == accountEmailAddress:

        # Update task end status
        updateStatus = taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "CLA_CREATION",
                "function": "talr-director",
                "message": incomingMessage
            }
        )

        laAccountId = incomingMessage['linkedAccountId']
        print("New linked account: " + laAccountId)

        updateAccountInfo = accountInfo.update_item(
            Key={
                'accountEmailAddress': accountEmailAddress
            },
            UpdateExpression='SET #accountId = :val1',
            ExpressionAttributeNames={'#accountId': "accountId"},
            ExpressionAttributeValues={':val1': incomingMessage['linkedAccountId']}
        )
    else:
        # Update task failure status
        updateStatus = taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "failed",
                "taskName": "CLA_CREATION",
                "function": "talr-director",
                "message": incomingMessage
            }
        )

        return {"code": "601", "requestId": requestId, "message": "ERROR: Linked account failed to create"}

    # Start linked account validation
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "CLA_VALIDATION",
            "function": "talr-director",
            "message": "Linked account: " + laAccountId
        }
    )

    # Payer account credentials
    payerAssumeRole = sts.assume_role(
        RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
        RoleSessionName="talrDirectorPayerAssumeRole"
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
        RoleArn="arn:aws:iam::" + laAccountId + ":role/PayerAccountAccessRole",
        RoleSessionName="talrDirectorLaAssumeRole"
    )
    laCredentials = laAssumeRole['Credentials']
    la_aws_access_key_id = laCredentials['AccessKeyId']
    la_aws_secret_access_key = laCredentials['SecretAccessKey']
    la_aws_session_token = laCredentials['SessionToken']

    # List roles in linked account to validate access
    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    laListRoles = laIam.list_roles()
    print(laListRoles)

    # Create IAM Account Alias in Linked Account
    accountIamAlias = accountCompanyCode + "-" + accountDivision.lower() + "-" + \
        accountTagShortProjectName + "-" + accountTagEnvironment
    laCreateAccountIamAlias = laIam.create_account_alias(
        AccountAlias=accountIamAlias
    )

    # Add account IAM alias to accountInfo table
    updateAccountInfo = accountInfo.update_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        },
        UpdateExpression='SET #accountIamAlias = :val1',
        ExpressionAttributeNames={'#accountIamAlias': "accountIamAlias"},
        ExpressionAttributeValues={':val1': accountIamAlias}
    )

    # Update task end status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "CLA_VALIDATION",
            "function": "talr-director",
            "message": "Linked account: " + laAccountId
        }
    )

    publishToTalrDispatchRequest = sns.publish(
        TopicArn=dispatchRequestArn,
        Message='{ "default" : { "requestId": "' + requestId + '", "accountEmailAddress": "' +
                accountEmailAddress + '" }, "lambda" : { "requestId": "' + requestId +
                '", "accountEmailAddress": "' + accountEmailAddress + '" }}'
    )
