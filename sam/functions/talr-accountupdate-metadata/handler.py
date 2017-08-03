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
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])

    try:
        print('context:resource-path', event['context']['resource-path'] == '/accounts')
        print('body-json:accountId', re.match("^[0-9]{12}$", event['body-json']['accountId']))
    except Exception as e:
        print(e)
        print("regex not matching any values passed in request")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # Header validation
    try:
        print('header:accountCbAlias', re.match("^[a-z]{3,4}-[a-z]{3,5}$", event['params']['header']['accountCbAlias']))

        # Test if the accountCbAlias key exists
        getCbInfo = cbInfo.get_item(
            Key={
                'accountCbAlias': event['params']['header']['accountCbAlias']
            }
        )

        # Test if the value of accountCbAlias is valid, it will be if cbInfo returns an entry.
        accountCbAlias = getCbInfo['Item']['accountCbAlias']

    except Exception as e:
        print(e)
        print("regex not matching any values passed in request")
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})

    # accountId validation
    accountId = None
    try:
        if event['context']['resource-path'] == '/accounts' and event['params']['querystring']['accountid']:
            if re.match("^[0-9]{12}$", event['params']['querystring']['accountid']) or \
                    re.match("^[0-9]{4}-[0-9]{4}-[0-9]{4}$", event['params']['querystring']['accountid']):

                accountId = re.sub('-', '', event['params']['querystring']['accountid'])
                stage = event['stage-variables']['stage']
                requestId = str(uuid.uuid4())
                accountIdFound = True
                print('accoountIdFound', accountIdFound)

                # Check if account exists
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

            else:
                accountIdFound = False
                print('accoountIdFound', accountIdFound)
    except KeyError as e:
        print(e)
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})


    # accountUpdate body request validation




    # if event['context']['resource-path'] == '/accounts' and \
    #         re.match("^[0-9]{12}$", event['body-json']['accountId']):
    #
    #     requestId = str(uuid.uuid4())
    #     accountId = event['body-json']['accountId']
    #     stage = event['stage-variables']['stage']
    #
    #     # Check if account already exists
    #     getAccountId = accountInfo.scan(
    #         ProjectionExpression='accountId, accountEmailAddress',
    #         FilterExpression=Attr('accountId').eq(accountId)
    #     )
    #
    #     if getAccountId['Count'] == 0:
    #         print("Account not found")
    #         raise Exception({"code": "4040", "message": "ERROR: Not found"})
    #
    #     elif int(getAccountId['Count']) > 0:
    #
    #         # Update accountInfo with new requestId
    #         accountInfo.update_item(
    #             Key={
    #                 'accountEmailAddress': getAccountId['Items'][0]['accountEmailAddress']
    #             },
    #             UpdateExpression='SET #requestId = :val1',
    #             ExpressionAttributeNames={'#requestId': "requestId"},
    #             ExpressionAttributeValues={':val1': requestId}
    #         )
    #
    #         # Build Lambda invoke payload
    #         message = {"requestId": requestId, "accountId": accountId, "accountEmailAddress": getAccountId['Items'][0]['accountEmailAddress'] }
    #         payload = {"Records": [{"Sns": {"Message": message}}]}
    #
    #         # Call Lambda
    #         awslambda.invoke(
    #             FunctionName='talr-cloudability-' + stage,
    #             InvocationType='Event',
    #             Payload=json.dumps(payload),
    #         )
    #
    #         return {"code": "2020", "message": "Request Accepted", "requestId": requestId}
    #
    # else:
    #     raise Exception({"code": "4000", "message": "ERROR: Bad request"})
