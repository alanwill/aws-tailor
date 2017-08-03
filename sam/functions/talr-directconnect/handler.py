# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import time
from base64 import b64decode

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
kms = boto3.client('kms')
sts = boto3.client('sts')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    dxInterface = dynamodb.Table(os.environ['TAILOR_TABLENAME_DXINTERFACE'])
    incomingMessage = event['Records'][0]['Sns']['Message'].split('\n')

    # Parse the SNS message with the Cloudformation response. Since it's not in JSON format, it needs to be converted
    # to a dictionary first
    cfnIncomingMessage = {}
    for line in incomingMessage:
        key = line.partition("=")[0]
        value = line.partition("=")[2].lstrip("'").rstrip("'")
        cfnIncomingMessage[key] = value
    print(cfnIncomingMessage)

    # Check each incoming event and determine whether the Stack has completed successfully, only proceed if yes
    # otherwise exit.
    try:
        if "arn:aws:cloudformation:" in cfnIncomingMessage['PhysicalResourceId'] and \
                        cfnIncomingMessage['ResourceStatus'] == "CREATE_COMPLETE" and \
                        cfnIncomingMessage['LogicalResourceId'] == "core":
            global stackId
            stackId = cfnIncomingMessage['StackId']
            physicalResourceId = cfnIncomingMessage['PhysicalResourceId']
            accountId = cfnIncomingMessage['Namespace']
            print("StackId:", stackId)
            print("PhysicalResourceId:", physicalResourceId)
            print("AccountId:", accountId)

            # Scan talr-accountInfo table for requestId
            getRequestId = accountInfo.scan(
                TableName=os.environ['TAILOR_TABLENAME_ACCOUNTINFO'],
                ProjectionExpression='requestId',
                FilterExpression=Attr('accountId').eq(accountId)
            )
            global requestId
            requestId = getRequestId['Items'][0]['requestId']
            print("requestId:", requestId)
        else:
            return "VPC not ready."
    except Exception as e:
        print(e)
        print("***VPC not ready.***")
        return "VPC not ready."

    # Update task start status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "DIRECTCONNECT",
            "function": "talr-directconnect",
            "message": stackId
        }
    )

    # Look up the accountEmailAddress from the known requestId
    getAccountEmailAddress = accountInfo.query(
        IndexName='gsiRequestId',
        KeyConditionExpression=Key('requestId').eq(requestId)
    )
    accountEmailAddress = getAccountEmailAddress['Items'][0]['accountEmailAddress']

    # Lookup accountInfo variables
    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    accountId = getAccountInfo['Item']['accountId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']
    accountCsId = getCbInfo['Item']['accountCsId']
    accountDxAsn = getCbInfo['Item']['accountDxAsn']
    accountDivision = getCbInfo['Item']['accountDivision'].lower()
    accountDxDc = getCbInfo['Item']['accountDxDc']

    # Determine region based on stackId
    region = stackId.split(":")[3]
    print("region:", region)

    # Decrypt DX auth key daemon password
    accountDxAuthKeyEncrypted = getCbInfo['Item']['accountDxAuthKeyEncrypted']

    for i in accountDxAuthKeyEncrypted:
        if i == region:
            accountDxAuthKey = bytes(kms.decrypt(CiphertextBlob=b64decode(accountDxAuthKeyEncrypted[region]))['Plaintext'])

    # Initialize credentials for core services account
    cs_aws_access_key_id, cs_aws_secret_access_key, cs_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountCsId)

    # Initialize credentials for linked account
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountId)

    # Lookup virtual private gateway from stack outputs
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )
    describeStack = laCfn.describe_stacks(
        StackName=stackId
    )
    for i in describeStack['Stacks'][0]['Outputs']:
        if i['OutputKey'] == "VirtualPrivateGateway":
            global virtualPrivateGateway
            virtualPrivateGateway = i['OutputValue']
        else:
            continue

    # Initialize Direct Connect client with Linked Account credentials
    laDx = boto3.client(
        'directconnect',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    # Initialize Direct Connect client with Core Services credentials
    csDx = boto3.client(
        'directconnect',
        region_name=region,
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token
    )

    # Describe connections in region
    describeConnections = csDx.describe_connections()
    print(describeConnections)

    if len(describeConnections['connections']) == 0:
        raise Exception('No DX connections detected')

    count = 1
    for i, connection in enumerate(describeConnections['connections']):
        dc = accountDxDc[region]

        if i == 0:
            # Query talr-dxInterface table for all unassigned regions in region
            getDxInterface = dxInterface.query(
                ConsistentRead=True,
                KeyConditionExpression=Key('divisionDcRegion').eq(accountDivision + dc + region),
                FilterExpression=Attr('state').eq('available')
            )
            print("Query for VI availability to talr-dxInterface returned:", getDxInterface)

            global nextVlan
            nextVlan = int(getDxInterface['Items'][0]['vlan']) + 100

        elif i == 1:
            getDxInterface = dxInterface.query(
                ConsistentRead=True,
                KeyConditionExpression=Key('divisionDcRegion').eq(accountDivision + dc + region) & Key('vlan').eq(str(nextVlan)),
                FilterExpression=Attr('state').eq('available')
            )
            print("Query for VI availability to talr-dxInterface returned:", getDxInterface)

        # Create DX virtual interface in Core Services account
        createVi = csDx.allocate_private_virtual_interface(
            connectionId=connection['connectionId'],
            ownerAccount=accountId,
            newPrivateVirtualInterfaceAllocation={
                'virtualInterfaceName': accountIamAlias + '-' + region + '-' + str(count),
                'vlan': int(getDxInterface['Items'][0]['vlan']),
                'asn': int(accountDxAsn),
                'authKey': accountDxAuthKey,
                'amazonAddress': getDxInterface['Items'][0]['amazonIp'],
                'customerAddress': getDxInterface['Items'][0]['customerIp']
            }
        )
        print(createVi)
        count += 1

        # Update interface status in talr-dxInterface table
        updateDxInterface = dxInterface.update_item(
            Key={'divisionDcRegion': getDxInterface['Items'][0]['divisionDcRegion'],
                 'vlan': getDxInterface['Items'][0]['vlan']},
            UpdateExpression="set #state = :v1, "
                             "#accountIamAlias = :v2, "
                             "#accountId = :v3, "
                             "#requestId = :v4",
            ExpressionAttributeNames={'#state': "state",
                                      '#accountIamAlias': "accountIamAlias",
                                      '#accountId': "accountId",
                                      '#requestId': "requestId"},
            ExpressionAttributeValues={':v1': "assigned",
                                       ':v2': accountIamAlias,
                                       ':v3': accountId,
                                       ':v4': requestId}
        )
        print(updateDxInterface)

        # Confirm DX virtual interface in linked account
        confirmVi = laDx.confirm_private_virtual_interface(
            virtualInterfaceId=createVi['virtualInterfaceId'],
            virtualGatewayId=virtualPrivateGateway
        )
        print(confirmVi)

    # Update task end status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "DIRECTCONNECT",
            "function": "talr-directconnect",
            "message": "-"
        }
    )

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

    # Initialize IAM client with Linked Account credentials
    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)
