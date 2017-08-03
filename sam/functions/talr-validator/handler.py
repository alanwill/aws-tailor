# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
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
sns = boto3.client('sns')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    adSecGroup = dynamodb.Table(os.environ['TAILOR_TABLENAME_ADSECGROUP'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    notifyRequestArn = os.environ['TAILOR_SNSARN_NOTIFY_REQUEST']
    eventsPushArn = os.environ['TAILOR_SNSARN_EVENTS_PUSH']
    incomingMessage = event['Records']

    # Process DynamoDB Streams events based on source
    requestIds = list()
    try:
        if incomingMessage[0]['dynamodb']['Keys']['requestId']['S']:

            # Extract unique request IDs from DynamoDB Streams event and store in requestIds
            for r in incomingMessage:
                if r['dynamodb']['Keys']['requestId']['S'] in requestIds:
                    continue
                else:
                    requestIds.append(r['dynamodb']['Keys']['requestId']['S'])
    except Exception as e:
        print(e)

        try:
            if incomingMessage[0]['dynamodb']['Keys']['groupName']['S']:
                groupName = incomingMessage[0]['dynamodb']['Keys']['groupName']['S']
                getRequestId = adSecGroup.get_item(
                    Key={
                        'groupName': groupName
                    }
                )
                requestId = getRequestId['Item']['requestId']
                requestIds.append(requestId)
            else:
                return
        except Exception as e:
            print(e)
            return

    # For each requestId found, process validation
    for r in requestIds:
        requestId = r
        print("Processing requestId:", requestId)

        # Look up the accountEmailAddress from the known requestId
        getAccountEmailAddress = accountInfo.query(
            IndexName='gsiRequestId',
            KeyConditionExpression=Key('requestId').eq(requestId)
        )

        # Look up accountCbAlias from derived accountEmailAddress
        # accountEmailAddress will not exist in cases where the request is a duplicate request
        try:
            accountEmailAddress = getAccountEmailAddress['Items'][0]['accountEmailAddress']
            getAccountInfo = accountInfo.get_item(
                Key={
                    'accountEmailAddress': accountEmailAddress
                }
            )
        except Exception as e:
            print("No email found for request ", requestId)
            print(e)
            return

        accountCbAlias = getAccountInfo['Item']['accountCbAlias']
        accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']
        accountTagLongProjectName = getAccountInfo['Item']['accountTagLongProjectName']
        accountTagShortProjectName = getAccountInfo['Item']['accountTagShortProjectName']
        accountEmailAddress = getAccountInfo['Item']['accountEmailAddress']

        try:
            accountRegulated = getAccountInfo['Item']['accountRegulated']
        except KeyError as e:
            accountRegulated = 'Unknown'

        try:
            requestorEmailAddress = getAccountInfo['Item']['requestorEmailAddress']
        except KeyError as e:
            requestorEmailAddress = 'Unknown'
        try:
            requestorFullName = getAccountInfo['Item']['requestorFullName']
        except KeyError as e:
            requestorFullName = 'Unknown'
        try:
            accountVpcCidr = getAccountInfo['Item']['accountVpcCidr']
        except KeyError as e:
            accountVpcCidr = 'Unknown'
        try:
            externalTransactionId = getAccountInfo['Item']['externalTransactionId']
        except KeyError as e:
            externalTransactionId = ''

        # Test if these variables are populated in accountInfo yet before continuing
        if 'accountIamAlias' in getAccountInfo['Item']:
            accountIamAlias = getAccountInfo['Item']['accountIamAlias']
            print("accountIamAlias:", accountIamAlias)
        else:
            print("accountIamAlias not set yet.")
            return "accountIamAlias not set yet."
        if 'accountId' in getAccountInfo['Item']:
            accountId = getAccountInfo['Item']['accountId']
            print("accountId:", accountId)
        else:
            return "accountId not set yet."

        # Look up accountSuccessCount from derived accountCbAlias
        getCbInfo = cbInfo.get_item(
            Key={
                'accountCbAlias': accountCbAlias
            }
        )
        accountDivision = getCbInfo['Item']['accountDivision']
        accountSupportTeamName = getCbInfo['Item']['accountSupportTeamName']
        accountAwsLoginPage = getCbInfo['Item']['accountAwsLoginPage']
        accountTaskSuccessCount = getCbInfo['Item']['accountTaskSuccessCount']
        print("accountTaskSuccessCount:", accountTaskSuccessCount)
        accountAdSecGroupCreateSuccessCount = getCbInfo['Item']['accountAdSecGroupCreateSuccessCount']
        print("accountAdSecGroupCreateSuccessCount:", accountAdSecGroupCreateSuccessCount)
        accountAdSecGroupRegulatedPopulateSuccessCount = \
            getCbInfo['Item']['accountAdSecGroupRegulatedPopulateSuccessCount']
        print("accountAdSecGroupRegulatedPopulateSuccessCount:", accountAdSecGroupRegulatedPopulateSuccessCount)
        accountAdSecGroupNonRegulatedPopulateSuccessCount = \
            getCbInfo['Item']['accountAdSecGroupNonRegulatedPopulateSuccessCount']
        print("accountAdSecGroupNonRegulatedPopulateSuccessCount:", accountAdSecGroupNonRegulatedPopulateSuccessCount)

        # Look up status of tasks to derive if account configuration is complete
        getTaskStatus = taskStatus.query(
            KeyConditionExpression=Key('requestId').eq(requestId) & Key('eventTimestamp').gt('1')
        )

        # Look up status of AD Security Groups to derive if all groups have been created
        getAdSecGroupStatus = adSecGroup.query(
            IndexName='gsiRequestId',
            KeyConditionExpression=Key('requestId').eq(requestId)
        )

        # Check how many tasks have completed
        taskCompleteCount = 0
        for p in getTaskStatus['Items']:
            if p['period'] == 'start':
                continue
            elif p['period'] == 'end':
                taskCompleteCount += 1
        print("taskCompleteCount:", taskCompleteCount)

        try:
            # Check how many AD Sec Groups are created and how many have members
            adSecGroupCreateCount = 0
            adSecGroupPopulateCount = 0
            for p in getAdSecGroupStatus['Items']:
                if p['getGroupValidation'] == 'created':
                    adSecGroupCreateCount += 1
                if p['getMembersValidation'] == 'populated':
                    adSecGroupPopulateCount += 1
                else:
                    continue
            print("adSecGroupCreateCount:", adSecGroupCreateCount)
            print("adSecGroupPopulateCount:", adSecGroupPopulateCount)
        except KeyError:
            print("KeyError: key not found")
            return

        validationCheck = validation_results(group_create_success_count_lookup=int(accountAdSecGroupCreateSuccessCount),
                                             group_create_success_count_calculated=adSecGroupCreateCount,
                                             regulated_group_populate_count_lookup=int(accountAdSecGroupRegulatedPopulateSuccessCount),
                                             nonregulated_group_populate_count_lookup=int(accountAdSecGroupNonRegulatedPopulateSuccessCount),
                                             group_populated_count_calculated=adSecGroupPopulateCount,
                                             regulated_account=accountRegulated,
                                             task_complete_count_lookup=int(accountTaskSuccessCount),
                                             task_complete_count_calculated=taskCompleteCount)
        print("validationCheck is", validationCheck)

        # Email content
        emailContentText = requestorFullName + ",\\nYour AWS account request for " + accountTagLongProjectName + " has been fulfilled.\\nTo log into your account go to " + accountAwsLoginPage + " and use your AD Admin credentials to authenticate.\\n\\nIf you have any questions about your account, contact the " + accountSupportTeamName + ".\\nThanks,\\nTailor"
        emailContentHtml = requestorFullName + ",<br><br>Your AWS account request for <b>" + accountTagLongProjectName + "</b> has been fulfilled. The Account Number is: " + accountId + ".<br><br>To log into your account go to " + accountAwsLoginPage + " and use your AD Admin credentials. <br><br>To manage who can access this account, the AD Security Group, <b>aws-" + accountDivision + "-" + accountId + "_" + accountTagShortProjectName + "-" + accountTagEnvironment + "-Application-Admins</b> has been created and you are the owner. You can submit a ServiceNow request to add or remove users as needed. NOTE: Only AD Admin accounts should be added to this group, regular accounts would not work.<br><br>If you have any questions about your account, contact the " + accountSupportTeamName + ".<br><br><i>Tailor</i>"

        # Test whether email sent flag has already been set.
        if "requestConfirmationEmail" not in getAccountInfo['Item']:
            requestConfirmationEmail = False
        elif getAccountInfo['Item']['requestConfirmationEmail'] == "Y":
            requestConfirmationEmail = True
        print("requestConfirmationEmail is", requestConfirmationEmail)

        # Check of the number of completed tasks matches the number expected
        # from DynamoDB and only send an email if one hasn't already been sent.
        if validationCheck is True and requestConfirmationEmail is False:
            publishToTalrNotifyRequest = sns.publish(
                TopicArn=notifyRequestArn,
                Message='{ "default" : { "requestId": "' + requestId + '", "requestorEmailAddress": "' + requestorEmailAddress + '", "emailSubject": "AWS Account Request Completed", "emailContentText": "' + emailContentText + '", "emailContentHtml": "' + emailContentHtml + '" }, "lambda" : { "requestId": "' + requestId + '", "requestorEmailAddress": "' + requestorEmailAddress + '", "emailSubject": "AWS Account Request Completed", "emailContentText": "' + emailContentText + '", "emailContentHtml": "' + emailContentHtml + '" }}'
            )

            # Update the accountInfo table with flag stating email has been sent.
            updateAccountInfo = accountInfo.update_item(
                Key={
                    'accountEmailAddress': accountEmailAddress
                },
                UpdateExpression='SET #requestConfirmationEmail = :val1',
                ExpressionAttributeNames={'#requestConfirmationEmail': "requestConfirmationEmail"},
                ExpressionAttributeValues={':val1': 'Y'}
            )

            # Publish events to SNS topic for external systems to consume
            publishToTalrEventsPush = sns.publish(
                TopicArn=eventsPushArn,
                Message='{\
                                "newAccount": {\
                                    "requestId": "' + requestId + '",\
                                    "requestorEmailAddress": "' + requestorEmailAddress + '",\
                                    "accountId": "' + accountId + '",\
                                    "accountIamAlias": "' + accountIamAlias + '",\
                                    "accountEmailAddress": "' + accountEmailAddress + '",\
                                    "externalTransactionId": "' + externalTransactionId + '",\
                                    "accountTagLongProjectName": "' + accountTagLongProjectName + '",\
                                    "requestorFullName": "' + requestorFullName + '",\
                                    "accountVpcCidr": "' + str(accountVpcCidr) + '"\
                                }\
                            }'
            )

    return


def validation_results(group_create_success_count_lookup, group_create_success_count_calculated,
                       regulated_group_populate_count_lookup, nonregulated_group_populate_count_lookup,
                       group_populated_count_calculated, regulated_account,
                       task_complete_count_lookup, task_complete_count_calculated):

    if regulated_account is False and \
            group_create_success_count_lookup <= group_create_success_count_calculated and \
            nonregulated_group_populate_count_lookup <= group_populated_count_calculated and \
            task_complete_count_lookup <= task_complete_count_calculated:

        validation = True

    elif regulated_account is True and \
            group_create_success_count_lookup <= group_create_success_count_calculated and \
            regulated_group_populate_count_lookup <= group_populated_count_calculated and \
            task_complete_count_lookup <= task_complete_count_calculated:

        validation = True

    else:

        validation = False

    return validation
