# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import datetime
import hashlib
import hmac

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
sts = boto3.client('sts')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])

    try:
        if event['message'] == 'scaleup':
            updateTable = boto3.client('dynamodb').update_table(
                TableName=os.environ['TAILOR_TABLENAME_ACCOUNTINFO'],
                ProvisionedThroughput={
                    'WriteCapacityUnits': 10
                }
            )
            return updateTable
    except Exception as e:
        print("Failure in try/catch ", e)

    # Look up all CBs in talr-cbInfo and process based on each.
    scanCbInfo = cbInfo.scan(
        ProjectionExpression='accountCbAlias'
    )

    for i in scanCbInfo['Items']:
        getCbInfo = cbInfo.get_item(
            Key={
                'accountCbAlias': i['accountCbAlias']
            }
        )

        accountCbId = getCbInfo['Item']['accountCbId']

        # Assuming Payer/CB role and extract credentials to be used by the Organizations calls
        payerAssumeRole = sts.assume_role(
            RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
            RoleSessionName="talrClaPayerAssumeRole"
        )
        payerCredentials = payerAssumeRole['Credentials']

        organizations = boto3.client(
            'organizations',
            region_name='us-east-1',
            aws_access_key_id=payerCredentials['AccessKeyId'],
            aws_secret_access_key=payerCredentials['SecretAccessKey'],
            aws_session_token=payerCredentials['SessionToken'],
        )

        count = 0
        accounts = list()
        nextToken = None

        # Call listAccounts API to get list of all accounts then store ouput in a list
        while True:
            if nextToken:
                listAccounts = organizations.list_accounts(
                    NextToken=nextToken
                )
            else:
                listAccounts = organizations.list_accounts()
            count += 1
            for i in listAccounts['Accounts']:
                accounts.append(i)

            try:
                if listAccounts['NextToken']:
                    nextToken = listAccounts['NextToken']
            except KeyError:
                break

        # For each account update it's status in talr-accountInfo. First, get all accounts from talr-accountInfo.
        getTailorAccounts = accountInfo.scan(
            ProjectionExpression='accountId, accountEmailAddress'
        )

        tailorAccountIds = list()
        for i in getTailorAccounts['Items']:
            # Try catch for cases where there's an email address with no accountId.
            # Should be rare but has been known to happen.
            try:
                tailorAccountIds.append(i['accountId'])
            except KeyError as e:
                print(e)

        tailorEmailAddresses = list()
        for i in getTailorAccounts['Items']:
            # Try catch for cases where there's an email address with no accountId.
            # Should be rare but has been known to happen.
            try:
                tailorEmailAddresses.append(i['accountEmailAddress'])
            except KeyError as e:
                print(e)

        # Loop through all the account received from Organizations
        for i in accounts:
            accountId = i['Id']
            emailAddress = i['Email']
            status = i['Status']
            # Loop through all the accounts from Organizations and compare with what's known to Tailor
            for ii in getTailorAccounts['Items']:
                # Try catch for cases where there's an email address with no accountId.
                # Should be rare but has been known to happen.
                try:
                    if accountId == ii['accountId']:
                        accountEmailAddress = ii['accountEmailAddress']
                        if 'accountStatus' not in ii or ii['accountStatus'] != status:
                            accountInfo.update_item(
                                Key={
                                    'accountEmailAddress': accountEmailAddress
                                },
                                UpdateExpression='SET #accountStatus = :val1',
                                ExpressionAttributeNames={'#accountStatus': "accountStatus"},
                                ExpressionAttributeValues={':val1': status}
                            )
                            break
                except KeyError as e:
                    print(e)
                    break
            # Loop for accounts in Organizations that are not in Tailor and add them.
            if accountId not in tailorAccountIds:
                accountInfo.put_item(
                    Item={
                        "accountEmailAddress": emailAddress,
                        "accountId": accountId,
                        "accountStatus": status,
                        "addedViaAccountReconcile": True,
                        "comment": "Account found in Organizations. Added by Tailor Account Reconcile function."
                    }
                )

            # Loop for accounts in Tailor with no accountId
            if emailAddress not in tailorEmailAddresses:
                accountInfo.put_item(
                    Item={
                        "accountEmailAddress": emailAddress,
                        "accountId": accountId,
                        "accountStatus": status,
                        "addedViaAccountReconcile": True,
                        "comment": "Account found in Organizations. Added by Tailor Account Reconcile function."
                    }
                )
    return
