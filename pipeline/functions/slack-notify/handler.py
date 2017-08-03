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
cp = boto3.client('codepipeline')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    slackChannelName = os.environ['SLACK_CHANNEL_NAME']
    slackWebhookUrl = os.environ['SLACK_WEBHOOK_URL']

    try:
        if "CodePipeline.job" in event:
            jobId = event['CodePipeline.job']['id']
            callSlack(slackChannelName, slackWebhookUrl, jobId)
            cp.put_job_success_result(
                jobId=jobId,
                executionDetails={
                    'summary': 'Notification posted to Slack',
                    'percentComplete': 100
                }
            )
            return

    except Exception as e:
        print(e)
        return "Cannot recognize input"


def callSlack(slack_channel_name, slack_webhook_url, job_id):
    getJobDetails = cp.get_job_details(
        jobId=job_id
    )

    pipelineName = getJobDetails['jobDetails']['data']['pipelineContext']['pipelineName']
    stageName = getJobDetails['jobDetails']['data']['pipelineContext']['stage']['name']

    getPipelineState = cp.get_pipeline_state(
        name=pipelineName
    )
    pipelineExecutionId = getPipelineState['stageStates'][0]['latestExecution']['pipelineExecutionId']

    slackMessage = {
        'channel': slack_channel_name,
        'username': "tailorbot",
        'icon_emoji': ":robot_face:",
        "attachments": [
        {
            "color": "good",
            "title": 'Pipeline %s (%s)' % (pipelineName, pipelineExecutionId),
            "text": 'The %s stage is executing' % (stageName),
            "mrkdwn_in": ["text"]
        }
        ]
    }

    # Send notification
    slackWebhookResponse = requests.post(slack_webhook_url, data=json.dumps(slackMessage))
    print(slackWebhookResponse)

    return
