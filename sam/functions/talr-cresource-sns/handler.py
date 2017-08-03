# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sts = boto3.client('sts')
awslambda = boto3.client('lambda')

def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    stage = event['ResourceProperties']['Stage']
    topicNamePrefix = event['ResourceProperties']['TopicNamePrefix']
    topicName = topicNamePrefix + '-' + stage
    requestType = event['RequestType']

    # Initialize a Session object in order to look up Config regions
    boto3Session = boto3.Session()

    # All Config regions
    snsRegions = boto3Session.get_available_regions(
        service_name='sns',
        partition_name='aws',
    )

    if "Create" in requestType:
        create_topics(snsRegions, topicName, context, event, stage)

    elif "Update" in requestType:
        create_topics(snsRegions, topicName, context, event, stage)

    elif "Delete" in requestType:
        delete_topics(snsRegions, topicName, context, event)

def cfn_response(response_status, response_data, reason, physical_resource_id, event, context):
    # Put together the response to be sent to the S3 pre-signed URL

    if reason:
        reason = reason
    else:
        reason = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name

    responseBody = {'Status': response_status,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': physical_resource_id,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': response_data
                    }
    print('Response Body:', responseBody)
    response = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
    if response.status_code != 200:
        print(response.text)
        raise Exception('Response error received.')
    return

def list_lambda_functions(stage):

    functionArns = list()
    whitelist = {'talr-vpciam-' + stage,
                 'talr-vpcflowlogs-' + stage,
                 'talr-vpcdns-' + stage,
                 'talr-directconnect-' + stage}

    lambdaFunctions = awslambda.list_functions()
    for i in lambdaFunctions['Functions']:
        if i['FunctionName'] in whitelist:
            functionArns.append(i['FunctionArn'])

    marker = True
    while marker is True:
        try:
            if lambdaFunctions['NextMarker']:
                lambdaFunctions = awslambda.list_functions(
                    Marker=lambdaFunctions['NextMarker']
                )
                for i in lambdaFunctions['Functions']:
                    if i['FunctionName'] in whitelist:
                        functionArns.append(i['FunctionArn'])
        except KeyError as e:
            print(e)
            marker = False

    return functionArns


def create_topics(sns_regions, topic_name, context, event, stage):

    # Get list of Lambda functions to subsribe
    functionArns = list_lambda_functions(stage)
    print(functionArns)

    failures = 0
    for region in sns_regions:

        # Set region to create topic
        sns = boto3.client(
            'sns',
            region_name=region
        )

        createTopic = sns.create_topic(
            Name=topic_name
        )
        print('CreateTopic response: ', createTopic)

        createTopicPolicy = sns.add_permission(
            TopicArn=createTopic['TopicArn'],
            Label='LinkedAccountPublishAccess',
            AWSAccountId=[
                '*',
            ],
            ActionName=[
                'Publish',
            ]
        )
        print('CreateTopicPolicy response: ', createTopicPolicy)

        # Subscribe each function to the SNS topic created
        if isinstance(functionArns, list):
            for i in functionArns:
                # Subscribe Lambda functions
                sns.subscribe(
                    TopicArn=createTopic['TopicArn'],
                    Protocol='lambda',
                    Endpoint=i
                )

        # Add invoke permission for each SNS topic created
        for i in functionArns:
            awslambda.add_permission(
                FunctionName=i,
                StatementId=region + 'SnsTopicPermission',
                Action='lambda:InvokeFunction',
                Principal='sns.amazonaws.com',
                SourceArn=createTopic['TopicArn'],
            )

        # Check if topic creation was successful
        if 'TopicArn' not in createTopic or createTopicPolicy['ResponseMetadata']['HTTPStatusCode'] != 200:
            failures = failures + 1

    if failures == 0:
        responseStatus = "SUCCESS"
        responseData = {"TopicName": topic_name}
        physicalResourceId = topic_name
        reason = ""
    else:
        reason = "At least one region failed to provision, check logs " + context.log_stream_name
        responseStatus = "FAILED"
        responseData = {}
        physicalResourceId = context.log_stream_name

    # Send response to Cloudformation
    cfn_response(response_status=responseStatus,
                 response_data=responseData,
                 physical_resource_id=physicalResourceId,
                 reason=reason,
                 event=event,
                 context=context)
    return

def delete_topics(sns_regions, topic_name, context, event):

    accountId = sts.get_caller_identity()['Account']
    failures = 0
    for region in sns_regions:

        # Set region to create topic
        sns = boto3.client(
            'sns',
            region_name=region
        )

        deleteTopic = sns.delete_topic(
            TopicArn='arn:aws:sns:' + region + ':' + accountId + ':' + topic_name
        )
        print('DeleteTopic response: ', deleteTopic)

        # Check if topic deletion was successful
        if deleteTopic['ResponseMetadata']['HTTPStatusCode'] != 200:
            failures = failures + 1

    if failures == 0:
        responseStatus = "SUCCESS"
        responseData = {}
        reason = ""
    else:
        reason = "At least one region failed to delete, check logs " + context.log_stream_name
        responseStatus = "FAILED"
        responseData = deleteTopic

    # Send response to Cloudformation
    cfn_response(response_status=responseStatus,
                 response_data=responseData,
                 physical_resource_id=context.log_stream_name,
                 reason=reason,
                 event=event,
                 context=context)
    return
