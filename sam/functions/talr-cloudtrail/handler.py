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


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])

    accountEmailAddress = None
    try:
        if event['Records'][0]['Sns']['Message']:
            incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
            accountEmailAddress = incomingMessage['lambda']['accountEmailAddress']
    except KeyError as e:
        print(e)
        try:
            if event['message']:
                accountEmailAddress = event['message']['accountEmailAddress']
        except KeyError as e:
            print(e)
            return "Could not interpret event."

    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    laAccountId = getAccountInfo['Item']['accountId']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']
    requestId = getAccountInfo['Item']['requestId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "CLOUDTRAIL",
            "function": "talr-cloudtrail",
            "message": accountEmailAddress
        }
    )

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']
    accountCloudtrailS3Bucket = getCbInfo['Item']['accountCloudtrailS3Bucket']

    laCredentials = initialize_la_services(account_cb_id=accountCbId, la_account_id=laAccountId)

    if check_trails(la_credentials=laCredentials, s3_bucket=accountCloudtrailS3Bucket) is True:
        # Update task end status
        taskStatus.put_item(
            Item={
                "requestId": requestId,
                "eventTimestamp": str(time.time()),
                "period": "end",
                "taskName": "CLOUDTRAIL",
                "function": "talr-cloudtrail",
                "message": accountEmailAddress
            }
        )
        return
    else:
        cleanup_resources(la_credentials=laCredentials,regions=all_regions(la_credentials=laCredentials))
        create_trails(la_credentials=laCredentials,
                      la_account_id=laAccountId,
                      s3_bucket=accountCloudtrailS3Bucket,
                      account_alias=accountIamAlias)

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp" : str(time.time()),
            "period" : "end",
            "taskName" : "CLOUDTRAIL",
            "function" : "talr-cloudtrail",
            "message" : accountEmailAddress
        }
    )

    return


def create_trails(la_credentials, la_account_id, s3_bucket, account_alias):

    laCloudtrail = boto3.client(
        'cloudtrail',
        region_name='us-east-1',
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )
    # Create Cloudtrail trail
    createTrail = laCloudtrail.create_trail(
        Name='default',
        S3BucketName=s3_bucket,
        S3KeyPrefix=account_alias,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True
    )

    # Start Cloudtrail trail logging
    startLogging = laCloudtrail.start_logging(
        Name='arn:aws:cloudtrail:us-east-1:' + la_account_id + ':trail/default'
    )

    # Describe trail
    describeTrail = laCloudtrail.describe_trails()
    print(describeTrail)

    return


def cleanup_resources(la_credentials, regions):

    # Clean up resources
    try:
        for region in regions:
            laCloudtrail = boto3.client(
                'cloudtrail',
                region_name=region,
                aws_access_key_id=la_credentials[0],
                aws_secret_access_key=la_credentials[1],
                aws_session_token=la_credentials[2],
            )
            describeTrail = laCloudtrail.describe_trails()
            for trail in describeTrail['trailList']:
                deleteTrail = laCloudtrail.delete_trail(
                    Name=trail['TrailARN']
                )
                print(deleteTrail)
    except Exception as e:
        print(e)
        print("No trails to delete")

    return


def all_regions(la_credentials):

    # Initialize a Session object in order to look up service regions
    boto3Session = boto3.Session(
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2]
    )
    regions = boto3Session.get_available_regions(
        service_name='cloudtrail',
        partition_name='aws',
    )

    return regions


def check_trails(la_credentials, s3_bucket):

    laCloudtrail = boto3.client(
        'cloudtrail',
        region_name='us-east-1',
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    checkTrail = laCloudtrail.describe_trails(
        trailNameList=['default'],
    )

    if len(checkTrail['trailList']) == 1 \
            and checkTrail['trailList'][0]['IsMultiRegionTrail'] is True \
            and checkTrail['trailList'][0]['S3BucketName'] == s3_bucket:
        return True
    else:
        return False


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

    return la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token
