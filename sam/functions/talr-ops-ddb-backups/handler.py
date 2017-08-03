# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import os
import sys
from time import gmtime, strftime

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
# sys.path.append(os.path.join(currentdir, "./vendored"))
sys.path.insert(0, os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import boto3

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    opsTbl = dynamodb.Table(os.environ['TAILOR_TABLENAME_OPS'])
    newImage = event['Records'][0]['dynamodb']['NewImage']
    tableName = event['Records'][0]['eventSourceARN'].split(':')[5].split('/')[1]
    sequenceNumber = event['Records'][0]['dynamodb']['SequenceNumber']
    changeDate = event['Records'][0]['dynamodb']['ApproximateCreationDateTime']

    getOpsTbl = opsTbl.get_item(
        Key={
            'layer': 'dynamodb'
        }
    )
    s3Bucket = getOpsTbl['Item']['backupBucket']

    putObject = s3.put_object(
        Body=str(event),
        Bucket=s3Bucket,
        Key=tableName + '/' + sequenceNumber,
        Tagging='ApproximateCreationDateTime=' + str(changeDate) +
                '&Month=' + str(strftime("%m", gmtime())) +
                '&Year=' + str(strftime("%Y", gmtime()))
    )

    """
    listChanges = s3.list_objects(
        Bucket=s3Bucket,
        Prefix=tableName,
    )
    """

    return
