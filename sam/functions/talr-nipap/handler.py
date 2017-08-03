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
cloudformation = boto3.resource('cloudformation')
s3 = boto3.client('s3')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    nipapCfn = dynamodb.Table(os.environ['TAILOR_TABLENAME_NIPAPCFN'])
    nipapcfnResponseArn = os.environ['TAILOR_SNSARN_NIPAPCFN_RESPONSE']
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
    accountEmailAddress = incomingMessage['lambda']['accountEmailAddress']

    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    requestId = getAccountInfo['Item']['requestId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']

    # Update task start status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "NIPAP_DAEMON",
            "function": "talr-nipap",
            "message": incomingMessage
        }
    )

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']

    getNipapCfn = nipapCfn.get_item(
        Key={
            'nipapAlias': accountCbAlias
        }
    )

    cfnDaemonTemplateObjectKey = getNipapCfn['Item']['cfnDaemonTemplateObjectKey']
    cfnAppName = getNipapCfn['Item']['cfnDaemonAppName']
    cfnEnvironmentName = getNipapCfn['Item']['cfnDaemonEnvironment']
    cfnApplicationSubnetAZ1 = getNipapCfn['Item']['cfnDaemonApplicationSubnetAZ1']
    cfnDaemonInstanceType = getNipapCfn['Item']['cfnDaemonInstanceType']
    cfnDaemonAmi = getNipapCfn['Item']['cfnDaemonAmi']
    cfnDaemonComponentsSecurityGroup = getNipapCfn['Item']['cfnDaemonComponentsSecurityGroup']
    cfnVpcId = getNipapCfn['Item']['cfnDaemonVpcId']

    # Download CFN template from S3 and pass contents to function to be used in Linked Account.
    getCfnTemplate = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key=cfnDaemonTemplateObjectKey
    )
    templateBody = getCfnTemplate['Body'].read()

    createDaemonInstance = cloudformation.create_stack(
        StackName='tailor-nipap-deamon-' + accountIamAlias + '-' + str(int(time.time())),
        TemplateBody=templateBody,
        Parameters=[
            {
                'ParameterKey': 'TailorRequestId',
                'ParameterValue': requestId
            },
            {
                'ParameterKey': 'AppName',
                'ParameterValue': cfnAppName
            },
            {
                'ParameterKey': 'EnvironmentName',
                'ParameterValue': cfnEnvironmentName
            },
            {
                'ParameterKey': 'ApplicationSubnetAZ1',
                'ParameterValue': cfnApplicationSubnetAZ1
            },
            {
                'ParameterKey': 'TailorNipapDaemonInstanceType',
                'ParameterValue': cfnDaemonInstanceType
            },
            {
                'ParameterKey': 'TailorNipapDaemonAmi',
                'ParameterValue': cfnDaemonAmi
            },
            {
                'ParameterKey': 'TailorComponentsSecurityGroup',
                'ParameterValue': cfnDaemonComponentsSecurityGroup
            },
            {
                'ParameterKey': 'VPCID',
                'ParameterValue': cfnVpcId
            }
        ],
        TimeoutInMinutes=15,
        NotificationARNs=[
            nipapcfnResponseArn,
        ],
        OnFailure='ROLLBACK'
    )
    print(createDaemonInstance)

    # Update task start status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "NIPAP_DAEMON",
            "function": "talr-nipap",
            "message": incomingMessage
        }
    )

    return
