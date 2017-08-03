# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys
import shutil

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sts = boto3.client('sts')
config = boto3.client('config')
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    accountId = sts.get_caller_identity()['Account']
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': event['accountCbAlias']
        }
    )
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']

    # Only deploy in regions where Config Rules exist
    boto3Session = boto3.Session()
    configRegions = boto3Session.get_available_regions(
        service_name='config',
        partition_name='aws',
    )

    functionName = 'talr-configrule-ec2notinpublicsubnet'
    # List files
    listObjects = s3.list_objects_v2(
        Bucket=accountTailorConfigBucket,
        Prefix='lambda/' + functionName,
    )

    # Directory Cleanup
    shutil.rmtree('/tmp/lambda/{}'.format(functionName), ignore_errors=True)
    os.makedirs('/tmp/lambda/{}'.format(functionName))

    # Download files
    for i in listObjects['Contents']:
        if i['Key'].endswith('/'):
            os.makedirs('/tmp/lambda/{}'.format('/tmp/' + i['Key']))
        elif not i['Key'].endswith('/'):
            s3.download_file(accountTailorConfigBucket, i['Key'], '/tmp/' + i['Key'])

    # Zip up files
    shutil.make_archive('/tmp/' + functionName, 'zip', '/tmp/lambda/' + functionName)

    for region in configRegions:
        if region != 'ca-central-1' and region != 'sa-east-1':
            # Set AWS Lambda client and region
            awslambda = boto3.client('lambda', region_name=region)

            # Delete function if it already exists
            try:
                deleteFunction = awslambda.delete_function(
                    FunctionName='talr-configrule-ec2notinpublicsubnet'
                )
            except Exception as e:
                print(e)

            # Create function
            createFunctionEc2NotInPublicSubnet = awslambda.create_function(
                FunctionName='talr-configrule-ec2notinpublicsubnet',
                Runtime='python2.7',
                Role='arn:aws:iam::' + accountId + ':role/tailor-' + context.invoked_function_arn.split(':')[7] + '-ConfigRuleLambdaFunctionRole',
                Handler='handler.handler',
                Code={
                    'ZipFile': open('/tmp/talr-configrule-ec2notinpublicsubnet.zip', 'rb').read(),
                },
                Description='Config Rule: EC2 not in Pubic subnet',
                Timeout=30,
                MemorySize=128,
                Environment={
                    'Variables': {
                        'TAILOR_TABLENAME_CBINFO': os.environ['TAILOR_TABLENAME_CBINFO'],
                        'TAILOR_TABLENAME_ACCOUNTINFO': os.environ['TAILOR_TABLENAME_ACCOUNTINFO']
                    }
                },
            )
            addPermissionFunctionEc2NotInPublicSubnet = awslambda.add_permission(
                FunctionName='talr-configrule-ec2notinpublicsubnet',
                StatementId='ConfigAccess',
                Action='lambda:InvokeFunction',
                Principal='config.amazonaws.com'
            )
