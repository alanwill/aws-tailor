# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import StringIO
import sys
import time
import zipfile

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sts = boto3.client('sts')
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    accountId = event['accountId']
    resultToken = event['resultToken']
    invokingEvent = json.loads(event['invokingEvent'])
    configurationItem = invokingEvent['configurationItem']
    isPrivate = True

    try:
        subnetId = configurationItem['configuration']['subnetId']
        vpcId = configurationItem['configuration']['vpcId']
    except TypeError as e:
        print(e)

    getAccountId = accountInfo.scan(
        ProjectionExpression='accountId, accountCbAlias',
        FilterExpression=Attr('accountId').eq(accountId)
    )
    accountCbAlias = getAccountId['Items'][0]['accountCbAlias']

    # Lookup payer account number
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']

    # If the resource is deleted mark the evaluation as compliant
    if configurationItem['configurationItemStatus'] == 'ResourceDeleted':
        evaluation = {
            "compliance_type": "COMPLIANT",
            "annotation": 'Its in private subnet'
        }
        put_evaluation(account_cb_id=accountCbId,
                       la_account_id=accountId,
                       invoking_event=invokingEvent,
                       evaluation=evaluation,
                       result_token=resultToken)

    # Intialize EC2 session
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountId)

    # Linked account credentials
    laEc2 = boto3.client(
        'ec2',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    lookupRouteTables = laEc2.describe_route_tables(
        Filters=[
            {
                'Name': 'route.destination-cidr-block',
                'Values': ['0.0.0.0/0']
            }
        ]
    )
    # If only default route table exists then
    # all subnets are automatically attached to this route table
    # Otherwise check if subnet is explicitly attached to another route table
    # Private subnet condition applies only when route doesn't contains
    # destination CIDR block = 0.0.0.0/0 or no Internet Gateway is attached
    for i in lookupRouteTables['RouteTables']:
        if i['VpcId'] == vpcId:
            for ii in i['Associations']:
                if ii['Main'] is True:
                    for iii in i['Routes']:
                        try:
                            if iii['DestinationCidrBlock'] == '0.0.0.0/0' and iii['GatewayId'].startswith('igw-'):
                                isPrivate = False
                        except KeyError as e:
                            print(e)
                else:
                    if ii['SubnetId'] == subnetId:
                        try:
                            for iii in i['Routes']:
                                if iii['DestinationCidrBlock'] == '0.0.0.0/0' and iii['GatewayId'].startswith('igw-'):
                                    isPrivate = False
                        except KeyError as e:
                            print(e)

    if isPrivate:
        evaluation = {
            "compliance_type": "COMPLIANT",
            "annotation": 'Its in private subnet'
        }
    else:
        evaluation = {
            "compliance_type": "NON_COMPLIANT",
            "annotation": 'Not in private subnet'
        }

    put_evaluation(account_cb_id=accountCbId,
                   la_account_id=accountId,
                   invoking_event=invokingEvent,
                   evaluation=evaluation,
                   result_token=resultToken)


def put_evaluation(account_cb_id, la_account_id, invoking_event, evaluation, result_token):

    # Intialize Config session
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=account_cb_id, la_account_id=la_account_id)

    # Linked account credentials
    laConfig = boto3.client(
        'config',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    pushToConfig = laConfig.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation['compliance_type'],
                "Annotation": evaluation['annotation'],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=result_token)
    return


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

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)
