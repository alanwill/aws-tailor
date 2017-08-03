# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import sys
import time
from datetime import datetime

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
s3 = boto3.client('s3')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
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
            global region
            region = stackId.split(":")[3]
            physicalResourceId = cfnIncomingMessage['PhysicalResourceId']
            laAccountId = cfnIncomingMessage['Namespace']
            print("StackId:", stackId)
            print("region:", region)
            print("PhysicalResourceId:", physicalResourceId)
            print("laAccountId:", laAccountId)

            # Scan talr-accountInfo table for requestId
            getRequestId = accountInfo.scan(
                TableName=os.environ['TAILOR_TABLENAME_ACCOUNTINFO'],
                ProjectionExpression='requestId',
                FilterExpression=Attr('accountId').eq(laAccountId)
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
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "VPCIAM",
            "function": "talr-vpciam",
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
    laAccountId = getAccountInfo['Item']['accountId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountVpcAzCount = getAccountInfo['Item']['accountVpcAzCount']

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCompanyCode = getCbInfo['Item']['accountCompanyCode']
    accountCbId = getCbInfo['Item']['accountCbId']
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']

    # Initialize credentials for linked account
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=laAccountId)

    # Lookup vpcid
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )
    # Look up CFN stack Outputs
    getStack = laCfn.describe_stacks(
        StackName='core'
    )

    # Extract internet subnets
    internetSubnets = getStack['Stacks'][0]['Outputs']
    for i in internetSubnets:
        if i['OutputKey'] == "InternetSubnets":
            subnets = i['OutputValue']
        else:
            continue

    # Initialize client services for linked account resource creation
    laIam = boto3.client(
        'iam',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    try:
        # Check if policy already exists
        getPolicy = laIam.get_policy(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'Ec2InternetSubnetDeny'
        )
        getPolicyDocument = laIam.get_policy_version(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'Ec2InternetSubnetDeny',
            VersionId=getPolicy['Policy']['DefaultVersionId']
        )
        internetSubnetDenyPolicy = getPolicyDocument['PolicyVersion']['Document']
        policyExists = True

    except Exception as e:
        print(e)
        print(accountCompanyCode.capitalize() + "Ec2InternetSubnetDeny does not already exist")

        # Pull IAM Deny policy from S3
        getInternetSubnetDenyPolicy = s3.get_object(
            Bucket=accountTailorConfigBucket,
            Key='iam/managed-policies/' + accountCompanyCode.capitalize() + 'Ec2InternetSubnetDeny.json'
        )
        internetSubnetDenyPolicy = json.loads(getInternetSubnetDenyPolicy['Body'].read())
        policyExists = False

    # Based on if a 2 or 3 AZ VPC strip out to subnet IDs and insert into the IAM policy Resource key
    if "2" in accountVpcAzCount:
        subnet1 = subnets.split(",", 1)[0]
        subnet2 = subnets.split(",", 1)[1]
        subnet1Arn = "arn:aws:ec2:" + region + ":" + laAccountId + ":subnet/" + subnet1
        subnet2Arn = "arn:aws:ec2:" + region + ":" + laAccountId + ":subnet/" + subnet2
        internetSubnetDenyPolicy['Statement'][0]['Resource'].append(subnet1Arn)
        internetSubnetDenyPolicy['Statement'][0]['Resource'].append(subnet2Arn)
        internetSubnetDenyPolicy['Statement'][0]['Resource'] = \
            list(set(internetSubnetDenyPolicy['Statement'][0]['Resource']))
    elif "3" in accountVpcAzCount:
        subnet1 = subnets.split(",", 1)[0]
        subnet2 = subnets.split(",", 1)[1]
        subnet3 = subnets.split(",", 1)[2]
        subnet1Arn = "arn:aws:ec2:" + region + ":" + laAccountId + ":subnet/" + subnet1
        subnet2Arn = "arn:aws:ec2:" + region + ":" + laAccountId + ":subnet/" + subnet2
        subnet3Arn = "arn:aws:ec2:" + region + ":" + laAccountId + ":subnet/" + subnet3
        internetSubnetDenyPolicy['Statement'][0]['Resource'].append(subnet1Arn)
        internetSubnetDenyPolicy['Statement'][0]['Resource'].append(subnet2Arn)
        internetSubnetDenyPolicy['Statement'][0]['Resource'].append(subnet3Arn)
        internetSubnetDenyPolicy['Statement'][0]['Resource'] = \
            list(set(internetSubnetDenyPolicy['Statement'][0]['Resource']))

    # Identify the ApplicationAdmins and ApplicationAdminsPlus roles
    listRoles = laIam.list_roles()

    applicationAdminsRoles = list()
    for i in listRoles['Roles']:
        if 'Application-Admin' in i['RoleName']:
            applicationAdminsRoles.append(i['RoleName'])

    if len(applicationAdminsRoles) == 1:
        applicationAdminRole = applicationAdminsRoles[0]
    elif len(applicationAdminsRoles) == 2:
        for i in [i for i, x in enumerate(applicationAdminsRoles) if 'AdminsPlus' in x]:
            if i == 1:
                applicationAdminsRole = applicationAdminsRoles[0]
                applicationAdminsPlusRole = applicationAdminsRoles[1]
            elif i == 0:
                applicationAdminsRole = applicationAdminsRoles[1]
                applicationAdminsPlusRole = applicationAdminsRoles[0]

    print("applicationAdminsRole", applicationAdminsRole)
    print("applicationAdminsPlusRole", applicationAdminsPlusRole)

    if policyExists is False:
        # Create managed policy
        createEc2InternetSubnetDenyPolicy = laIam.create_policy(
            PolicyName=accountCompanyCode.capitalize() + 'Ec2InternetSubnetDeny',
            PolicyDocument=json.dumps(internetSubnetDenyPolicy),
            Description='EC2 Internet Subnet Launch Deny Policy'
        )

        # Attach policy to both roles
        laIam.attach_role_policy(
            RoleName=applicationAdminsRole,
            PolicyArn=createEc2InternetSubnetDenyPolicy['Policy']['Arn']
        )
        laIam.attach_role_policy(
            RoleName=applicationAdminsPlusRole,
            PolicyArn=createEc2InternetSubnetDenyPolicy['Policy']['Arn']
        )
    elif policyExists is True:
        laIam.create_policy_version(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'Ec2InternetSubnetDeny',
            PolicyDocument=json.dumps(internetSubnetDenyPolicy),
            SetAsDefault=True
        )

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "VPCIAM",
            "function": "talr-vpciam",
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
    boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")
