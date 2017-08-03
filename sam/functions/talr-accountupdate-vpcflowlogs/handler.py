# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Attr
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
        print('context:resource-path', event['context']['resource-path'] == '/vpcflowlogs')
        print('body-json:region', re.match("^us-[a-z]{4}-[1|2]$", event['body-json']['region']))
        print('body-json:stackName', re.match("^[0-9a-z|_-]{4,35}$", event['body-json']['stackName']))
        print('body-json:accountId', re.match("^[0-9]{12}$", event['body-json']['accountId']))
        print('header:accountCbAlias', event['params']['header']['accountCbAlias'])
    except Exception as e:
        print(e)
        print("regex not matching any values passed in request")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # VPC Flow Logs logic
    if event['context']['resource-path'] == '/vpcflowlogs' and \
            re.match("^[0-9a-z|_-]{4,35}$", event['body-json']['stackName']) and \
            re.match("^us-[a-z]{4}-[1|2]$", event['body-json']['region']) and \
            re.match("^[0-9]{12}$", event['body-json']['accountId']) and \
            re.match("^[a-z-]{4,15}$", event['params']['header']['accountCbAlias']):

        requestId = str(uuid.uuid4())
        region = event['body-json']['region']
        accountId = event['body-json']['accountId']
        stackName = event['body-json']['stackName']
        accountCbAlias = event['params']['header']['accountCbAlias']
        functionAlias = event['stage-variables']['functionAlias']

        # Check if account already exists
        getAccountId = accountInfo.scan(
            ProjectionExpression='accountId, accountEmailAddress',
            FilterExpression=Attr('accountId').eq(accountId)
        )

        if getAccountId['Count'] == 0:
            print("Account not found")
            raise Exception({"code": "4040", "message": "ERROR: Not found"})

        elif int(getAccountId['Count']) > 0:

            # Update accountInfo with new requestId
            updateAccountInfo = accountInfo.update_item(
                Key={
                    'accountEmailAddress': getAccountId['Items'][0]['accountEmailAddress']
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

            # Lookup stackId
            laCfn = boto3.client(
                'cloudformation',
                region_name=region,
                aws_access_key_id=la_aws_access_key_id,
                aws_secret_access_key=la_aws_secret_access_key,
                aws_session_token=la_aws_session_token,
            )
            try:
                describeStack = laCfn.describe_stacks(
                    StackName=stackName
                )
                stackId = describeStack['Stacks'][0]['StackId']
            except Exception as e:
                print(e)
                print("Stack not found")
                raise Exception({"code": "4040", "message": "ERROR: Not found"})

            # Build Lambda invoke payload
            message = "StackId='" + stackId + "'\nLogicalResourceId='core'\nNamespace='" + accountId + "'\nPhysicalResourceId='" + stackId + "'\nResourceStatus='CREATE_COMPLETE'\nStackName='" + stackName + "'\n"
            payload = {"Records": [{"Sns": {"Message": message}}]}

            # Call Lambda
            invokeVpcFlowLogs = awslambda.invoke(
                FunctionName='talr-vpcflowlogs',
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