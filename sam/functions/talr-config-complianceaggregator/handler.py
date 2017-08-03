# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
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
    configRulesCompliance = dynamodb.Table(os.environ['TAILOR_TABLENAME_CONFIGRULESCOMPLIANCE'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    accountId = event['accountId']

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

    # Intialize Config session
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountId)

    # Only deploy in regions where Config Rules exist
    boto3Session = boto3.Session()
    configRegions = boto3Session.get_available_regions(
        service_name='config',
        partition_name='aws',
    )

    for region in configRegions:
        if region != 'ca-central-1' and region != 'sa-east-1' and region != 'ap-south-1':
            # Linked account credentials
            laConfig = boto3.client(
                'config',
                region_name=region,
                aws_access_key_id=la_aws_access_key_id,
                aws_secret_access_key=la_aws_secret_access_key,
                aws_session_token=la_aws_session_token,
            )

            # Get list of rules in account
            getRules = laConfig.describe_config_rules()

            configRules = list()
            for i in getRules['ConfigRules']:
                if i['ConfigRuleState'] == 'ACTIVE':
                    configRules.append(i['ConfigRuleName'])
                else:
                    pass

            # Check rule compliance status
            checkComplianceStatus = laConfig.describe_compliance_by_config_rule(
                ConfigRuleNames=configRules
            )

            # Check evaluation status
            checkEvaluationStatus = laConfig.describe_config_rule_evaluation_status(
                ConfigRuleNames=configRules
            )

            for i in checkComplianceStatus['ComplianceByConfigRules']:
                pollTimestamp = str(time.time())
                updateConfigRulesCompliance = configRulesCompliance.put_item(
                    Item={
                        "accountId": accountId,
                        "pollTimestamp": pollTimestamp,
                        "ruleName": i['ConfigRuleName'],
                        "complianceStatus": i['Compliance']['ComplianceType']
                    }
                )

                for ii in checkEvaluationStatus['ConfigRulesEvaluationStatus']:
                    if ii['ConfigRuleName'] == i['ConfigRuleName']:
                        try:
                            updateConfigRulesCompliance = configRulesCompliance.update_item(
                                Key={
                                    'accountId': accountId,
                                    'pollTimestamp': pollTimestamp
                                },
                                UpdateExpression='SET #ruleName = :val1, '
                                                 '#lastSuccessfulInvocationTime = :val2, '
                                                 '#ruleArn = :val3, '
                                                 '#lastSuccessfulEvaluationTime = :val4, '
                                                 '#region = :val5, '
                                                 '#lastErrorMessage = :val6, '
                                                 '#lastErrorCode = :val7',
                                ExpressionAttributeNames={'#ruleName': 'ruleName',
                                                          '#lastSuccessfulInvocationTime': 'lastSuccessfulInvocationTime',
                                                          '#ruleArn': 'ruleArn',
                                                          '#lastSuccessfulEvaluationTime': 'lastSuccessfulEvaluationTime',
                                                          '#region': 'region',
                                                          '#lastErrorMessage': 'lastErrorMessage',
                                                          '#lastErrorCode': 'lastErrorCode'},
                                ExpressionAttributeValues={':val1': ii['ConfigRuleName'],
                                                           ':val2': ii['LastSuccessfulInvocationTime'].strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                           ':val3': ii['ConfigRuleArn'],
                                                           ':val4': ii['LastSuccessfulEvaluationTime'].strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                           ':val5': ii['ConfigRuleArn'].split(":")[3],
                                                           ':val6': ii['LastErrorMessage'],
                                                           ':val7': ii['LastErrorCode']}
                            )
                        except KeyError:
                            updateConfigRulesCompliance = configRulesCompliance.update_item(
                                Key={
                                    'accountId': accountId,
                                    'pollTimestamp': pollTimestamp
                                },
                                UpdateExpression='SET #ruleName = :val1, '
                                                 '#ruleArn = :val3, '
                                                 '#region = :val5',
                                ExpressionAttributeNames={'#ruleName': 'ruleName',
                                                          '#ruleArn': 'ruleArn',
                                                          '#region': 'region'},
                                ExpressionAttributeValues={':val1': ii['ConfigRuleName'],
                                                           ':val3': ii['ConfigRuleArn'],
                                                           ':val5': ii['ConfigRuleArn'].split(":")[3]}
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

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)
