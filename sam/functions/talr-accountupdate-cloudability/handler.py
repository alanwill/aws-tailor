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
dynamodb = boto3.resource('dynamodb')
awslambda = boto3.client('lambda')
sts = boto3.client('sts')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])

    try:
        print('context:resource-path', event['context']['resource-path'] == '/cloudability/{accountId}')
        print('path:accountId', re.match("^[0-9]{12}$", event['params']['path']['accountId']))
    except Exception as e:
        print(e)
        print("regex not matching any values passed in request")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # Payload processing logic
    if event['context']['resource-path'] == '/cloudability/{accountId}' and \
            re.match("^[0-9]{12}$", event['params']['path']['accountId']):

        requestId = str(uuid.uuid4())
        accountId = event['params']['path']['accountId']
        stage = event['stage-variables']['stage']

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
            accountInfo.update_item(
                Key={
                    'accountEmailAddress': getAccountId['Items'][0]['accountEmailAddress']
                },
                UpdateExpression='SET #requestId = :val1',
                ExpressionAttributeNames={'#requestId': "requestId"},
                ExpressionAttributeValues={':val1': requestId}
            )

            # Build Lambda invoke payload
            message = {"requestId": requestId,
                       "accountId": accountId,
                       "accountEmailAddress": getAccountId['Items'][0]['accountEmailAddress']}
            payload = {"message": message}

            # Call Lambda
            awslambda.invoke(
                FunctionName='talr-cloudability-' + stage,
                InvocationType='Event',
                Payload=json.dumps(payload),
            )

            return {"code": "2020", "message": "Request Accepted", "requestId": requestId}

    else:
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})
