# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import re

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
from netaddr import IPNetwork, IPAddress

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    accountIdFound = None
    ipAddressFound = None
    accountEmailAddressFound = None

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
    try:
        if event['context']['resource-path'] == '/accounts' and event['params']['querystring']['accountid']:
            if re.match("^[0-9]{12}$", event['params']['querystring']['accountid']) or \
                    re.match("^[0-9]{4}-[0-9]{4}-[0-9]{4}$", event['params']['querystring']['accountid']):

                accountId = re.sub('-', '', event['params']['querystring']['accountid'])
                accountIdFound = True
                print('accoountIdFound', accountIdFound)
            else:
                accountIdFound = False
                print('accoountIdFound', accountIdFound)
    except KeyError as e:
        print(e)
        print("No accountId or bad accountId passed")
        accountIdFound = False
        print('accoountIdFound', accountIdFound)

    # email address validation
    try:
        if event['context']['resource-path'] == '/accounts' and event['params']['querystring']['emailaddress']:
            if re.match("^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$",
                        event['params']['querystring']['emailaddress']):

                accountEmailAddress = event['params']['querystring']['emailaddress']
                accountEmailAddressFound = True
                print('accountEmailAddressFound', accountEmailAddressFound)
            else:
                accountEmailAddressFound = False
                print('accountEmailAddressFound', accountEmailAddressFound)
    except KeyError as e:
        print(e)
        print("No emailaddress or bad emailaddress passed")
        accountEmailAddressFound = False
        print('accountEmailAddressFound', accountEmailAddressFound)

    # ip address validation
    try:
        if event['context']['resource-path'] == '/accounts' and event['params']['querystring']['ipaddress']:
            if re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                        event['params']['querystring']['ipaddress']):

                ipAddress = event['params']['querystring']['ipaddress']
                ipAddressFound = True
                print('ipAddressFound', ipAddressFound)
            else:
                ipAddressFound = False
                print('ipAddressFound', ipAddressFound)
    except KeyError as e:
        print(e)
        print("No ipaddress or bad ipaddress passed")
        ipAddressFound = False
        print('ipAddressFound', ipAddressFound)

    # test whether no query parameters were passed
    if accountIdFound is False and accountEmailAddressFound is False and ipAddressFound is False:
        raise Exception({"code": "4000", "message": "ERROR: Bad request"})
    elif accountIdFound is True:
        getAccountInfo = accountInfo.query(
            IndexName='gsiAccountId',
            KeyConditionExpression=Key('accountId').eq(accountId)
        )
        if getAccountInfo['Count'] >= 1:
            return {'accountId': getAccountInfo['Items'][0]['accountId'],
                    'accountStatus': getAccountInfo['Items'][0]['accountStatus'],
                    'emailAddress': getAccountInfo['Items'][0]['accountEmailAddress'],
                    'regulated': getAccountInfo['Items'][0]['accountRegulated'],
                    'accountName': getAccountInfo['Items'][0]['accountTagLongProjectName'],
                    'costCenter': getAccountInfo['Items'][0]['accountTagCostCenter'],
                    'environment': getAccountInfo['Items'][0]['accountTagEnvironment'],
                    'department': getAccountInfo['Items'][0]['requestorDepartment'],
                    'requestorName': getAccountInfo['Items'][0]['requestorFullName'],
                    'technicalContactName': getAccountInfo['Items'][0]['accountTechnicalContactFullName']
                    }
        elif getAccountInfo['Count'] == 0:
            raise Exception({"code": "4040", "message": "ERROR: Not found"})
    elif accountEmailAddressFound is True:
        try:
            getAccountInfo = accountInfo.get_item(
                Key={
                    'accountEmailAddress': accountEmailAddress
                }
            )
            return {'accountId': getAccountInfo['Item']['accountId'],
                    'accountStatus': getAccountInfo['Item']['accountStatus'],
                    'emailAddress': getAccountInfo['Item']['accountEmailAddress'],
                    'regulated': getAccountInfo['Item']['accountRegulated'],
                    'accountName': getAccountInfo['Item']['accountTagLongProjectName'],
                    'costCenter': getAccountInfo['Item']['accountTagCostCenter'],
                    'environment': getAccountInfo['Item']['accountTagEnvironment'],
                    'department': getAccountInfo['Item']['requestorDepartment'],
                    'requestorName': getAccountInfo['Item']['requestorFullName'],
                    'technicalContactName': getAccountInfo['Item']['accountTechnicalContactFullName']
                    }
        except KeyError as e:
            print(e)
            print("No account found for given email address")
            raise Exception({"code": "4040", "message": "ERROR: Not found"})
    elif ipAddressFound is True:

        getAccountInfo = accountInfo.scan(
            ProjectionExpression='#accountVpcCidr,'
                                 'accountId,accountEmailAddress,'
                                 'accountRegulated,'
                                 'accountStatus,'
                                 'accountTagLongProjectName,'
                                 'requestorFullName,'
                                 'accountTechnicalContactFullName',
            FilterExpression='attribute_exists (#accountVpcCidr)',
            ExpressionAttributeNames={'#accountVpcCidr': 'accountVpcCidr'}
        )

        for i in getAccountInfo['Items']:
            if i['accountVpcCidr']['us-west-1']:
                if IPAddress(ipAddress) in IPNetwork(i['accountVpcCidr']['us-west-1']):
                    return {'accountId': i['accountId'],
                            'accountStatus': i['accountStatus'],
                            'emailAddress': i['accountEmailAddress'],
                            'regulated': i['accountRegulated'],
                            'accountName': i['accountTagLongProjectName'],
                            'requestorName': i['requestorFullName'],
                            'technicalContactName': i['accountTechnicalContactFullName'],
                            'vpcCidr': i['accountVpcCidr']
                            }
                else:
                    pass
            elif i['accountVpcCidr']['us-west-2']:
                if IPAddress(ipAddress) in IPNetwork(i['accountVpcCidr']['us-west-2']):
                    return {'accountId': i['accountId'],
                            'accountStatus': i['accountStatus'],
                            'emailAddress': i['accountEmailAddress'],
                            'regulated': i['accountRegulated'],
                            'accountName': i['accountTagLongProjectName'],
                            'requestorName': i['requestorFullName'],
                            'technicalContactName': i['accountTechnicalContactFullName'],
                            'vpcCidr': i['accountVpcCidr']
                            }
                else:
                    pass
            elif i['accountVpcCidr']['us-east-1']:
                if IPAddress(ipAddress) in IPNetwork(i['accountVpcCidr']['us-east-1']):
                    return {'accountId': i['accountId'],
                            'accountStatus': i['accountStatus'],
                            'emailAddress': i['accountEmailAddress'],
                            'regulated': i['accountRegulated'],
                            'accountName': i['accountTagLongProjectName'],
                            'requestorName': i['requestorFullName'],
                            'technicalContactName': i['accountTechnicalContactFullName'],
                            'vpcCidr': i['accountVpcCidr']
                            }
                else:
                    pass

    if event['context']['resource-path'] == '/accounts/ids':
        getAccountInfo = accountInfo.scan(
            ProjectionExpression='accountId',
            FilterExpression=Attr('accountId').exists() & Attr('accountStatus').eq('ACTIVE')
        )
        accountIds = list()
        for i in getAccountInfo['Items']:
            accountIds.append(i['accountId'])

        return {'accountCbAlias': accountCbAlias,
                'accountIds': accountIds,
                'count': getAccountInfo['Count']}
