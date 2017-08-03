# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys
from base64 import b64decode

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
kms = boto3.client('kms')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    opsTbl = dynamodb.Table(os.environ['TAILOR_TABLENAME_OPS'])
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])

    getOpsTbl = opsTbl.get_item(
        Key={
            'layer': 'slack'
        }
    )
    slackChannelName = getOpsTbl['Item']['slackChannelName']
    slackWebhookEncrypted = getOpsTbl['Item']['slackWebhookEncrypted']
    slackHookUrl = "https://" + kms.decrypt(CiphertextBlob=b64decode(slackWebhookEncrypted))['Plaintext']

    try:
        if "Errors" in incomingMessage['Trigger']['MetricName'] \
                and "AWS/Lambda" in incomingMessage['Trigger']['Namespace']:
            newStateValue = incomingMessage['NewStateValue']
            reasonStateReason = incomingMessage['NewStateReason']
            functionName = incomingMessage['Trigger']['Dimensions'][0]['value']
            slackMessage = {
                'channel': slackChannelName,
                'username': "tailorbot",
                'icon_emoji': ":robot_face:",
                "attachments": [
                {
                    "color": "danger",
                    "title": functionName,
                    "text": "Has errors and is now in state %s: %s" % (newStateValue, reasonStateReason),
                    "mrkdwn_in": ["text"]
                }
                ]
            }

            # Send notification
            slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
            print(slackWebhookResponse)
            return
    except Exception as e:
        print(e)
        print("Input not a Lambda error metric")

    try:
        if "Duration" in incomingMessage['Trigger']['MetricName'] \
                and "AWS/Lambda" in incomingMessage['Trigger']['Namespace']:
            reasonStateReason = incomingMessage['NewStateReason']
            functionName = incomingMessage['Trigger']['Dimensions'][0]['value']
            slackMessage = {
                'channel': slackChannelName,
                'username': "tailorbot",
                'icon_emoji': ":robot_face:",
                "attachments": [
                    {
                        "color": "warning",
                        "title": functionName,
                        "text": "Took longer than threshold: %s" % (reasonStateReason),
                        "mrkdwn_in": ["text"]
                    }
                ]
            }

            # Send notification
            slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
            print(slackWebhookResponse)
            return
    except Exception as e:
        print(e)
        print("Input not a Lambda duration metric")

    try:
        if "ReadThrottleEvents" in incomingMessage['Trigger']['MetricName'] \
                and "AWS/DynamoDB" in incomingMessage['Trigger']['Namespace']:
            reasonStateReason = incomingMessage['NewStateReason']
            tableName = incomingMessage['Trigger']['Dimensions'][0]['value']
            slackMessage = {
                'channel': slackChannelName,
                'username': "tailorbot",
                'icon_emoji': ":robot_face:",
                "attachments": [
                    {
                        "color": "danger",
                        "title": tableName,
                        "text": "Table %s is being throttled. Alert: %s" % (tableName, reasonStateReason),
                        "mrkdwn_in": ["text"]
                    }
                ]
            }

            # Send notification
            slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
            print(slackWebhookResponse)
            return
    except Exception as e:
        print(e)
        print("Input not a DynamoDB ReadThrottleEvents metric")

    try:
        if "newAccount" in incomingMessage:
            requestorFullName = incomingMessage['newAccount']['requestorFullName']
            accountTagLongProjectName = incomingMessage['newAccount']['accountTagLongProjectName']
            accountId = incomingMessage['newAccount']['accountId']
            requestId = incomingMessage['newAccount']['requestId']
            accountEmailAddress = incomingMessage['newAccount']['accountEmailAddress']
            slackMessage = {
                'channel': slackChannelName,
                'username': "tailorbot",
                'icon_emoji': ":robot_face:",
                "attachments": [
                    {
                        "color": "good",
                        "title": "New Account",
                        "text": "%s created account %s (%s) for %s via requestId %s" % (requestorFullName,
                                                                                        accountId,
                                                                                        accountEmailAddress,
                                                                                        accountTagLongProjectName,
                                                                                        requestId),
                        "mrkdwn_in": ["text"]
                    }
                ]
            }

            # Send notification
            slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
            print(slackWebhookResponse)
            return
    except Exception as e:
        print(e)
        print("Input not a newAccount notification")

    try:
        slackMessage = {
            'channel': slackChannelName,
            'username': "tailorbot",
            'icon_emoji': ":robot_face:",
            "attachments": [
                {
                    "title": "Untrapped Error",
                    "text": "Message: %s" % (incomingMessage),
                    "mrkdwn_in": ["text"]
                }
            ]
        }

        # Send notification
        slackWebhookResponse = requests.post(slackHookUrl, data=json.dumps(slackMessage))
        print(slackWebhookResponse)
        return
    except Exception as e:
        print(e)
        print("Cannot recognize event input")

    return
