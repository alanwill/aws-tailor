# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys
import time
from base64 import b64decode
from botocore.exceptions import ClientError

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
iam = boto3.client('iam')
sts = boto3.client('sts')
dynamodb = boto3.resource('dynamodb')
kms = boto3.client('kms')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])

    accountEmailAddress = None
    incomingMessage = None
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
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountTagLongProjectName = getAccountInfo['Item']['accountTagLongProjectName']
    accountTagCostCenter = getAccountInfo['Item']['accountTagCostCenter']
    accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']
    accountTechnicalContactFullName = getAccountInfo['Item']['accountTechnicalContactFullName']
    accountStatus = getAccountInfo['Item']['accountStatus']
    requestorDepartment = getAccountInfo['Item']['requestorDepartment']
    requestorDivision = requestorDepartment.split('-')[0]
    requestId = getAccountInfo['Item']['requestId']

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']
    cloudabilityAuthTokenEncrypted = getCbInfo['Item']['cloudabilityAuthTokenEncrypted']
    cloudabilityOrganizationId = getCbInfo['Item']['cloudabilityOrganizationId']
    cloudabilityAccountGroupMap = getCbInfo['Item']['cloudabilityAccountGroupMap']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "CLOUDABILITY",
            "function": "talr-cloudability",
            "message": incomingMessage
        }
    )

    # Decrypt Cloudability auth token
    cloudabilityAuthToken = kms.decrypt(CiphertextBlob=b64decode(cloudabilityAuthTokenEncrypted))['Plaintext']

    # Initialize credentials for linked account
    laCredentials = initialize_la_services(account_cb_id=accountCbId, la_account_id=laAccountId)

    # Verify account state in Cloudablity
    cloudabilityState = verify_account(auth_token=cloudabilityAuthToken, la_account_id=laAccountId)

    if 'no_credentials_found' in cloudabilityState['state']:
        print(cloudabilityState['state'])
        # Get IAM role info from Cloudability
        roleInfo = create_credentials(auth_token=cloudabilityAuthToken,
                           organization_id=cloudabilityOrganizationId,
                           la_account_id=laAccountId)

        # Create IAM role in linked account
        create_role(role_name=roleInfo['roleName'],
                    external_id=roleInfo['externalId'],
                    cloudability_account_id=roleInfo['trustedAccountId'],
                    la_credentials=laCredentials)

        # Delete existing IAM keys and Managed policy, if they exist
        delete_old_keys(la_credentials=laCredentials,
                        la_account_id=laAccountId)

        update_account_data(auth_token=cloudabilityAuthToken,
                            la_account_id=laAccountId,
                            account_cc=accountTagCostCenter,
                            account_env=accountTagEnvironment,
                            account_status=accountStatus,
                            account_dept=requestorDepartment,
                            account_division=requestorDivision,
                            account_owner=accountTechnicalContactFullName,
                            account_name=accountTagLongProjectName,
                            account_group_map=cloudabilityAccountGroupMap)

    elif 'aws_user' in cloudabilityState['state']:
        print(cloudabilityState['state'])
        # Get migrate account to role enabled on Cloudability
        migrateToRole = migrate_to_role(auth_token=cloudabilityAuthToken,
                                        credential_id=cloudabilityState['credentialId'],
                                        la_account_id=laAccountId)

        # Create IAM role in linked account
        create_role(role_name=migrateToRole['roleName'],
                    external_id=migrateToRole['externalId'],
                    cloudability_account_id=migrateToRole['trustedAccountId'],
                    la_credentials=laCredentials)

        # Delete existing IAM keys and Managed policy, if they exist
        delete_old_keys(la_credentials=laCredentials,
                        la_account_id=laAccountId)

        update_account_data(auth_token=cloudabilityAuthToken,
                            la_account_id=laAccountId,
                            account_cc=accountTagCostCenter,
                            account_env=accountTagEnvironment,
                            account_status=accountStatus,
                            account_dept=requestorDepartment,
                            account_division=requestorDivision,
                            account_owner=accountTechnicalContactFullName,
                            account_name=accountTagLongProjectName,
                            account_group_map=cloudabilityAccountGroupMap)

    elif 'aws_role' in cloudabilityState['state']:
        print(cloudabilityState['state'])
        # Get credential uuid
        credentialUuid = cloudabilityState['credentialId']

        # Check credential info
        roleInfo = check_credentials(auth_token=cloudabilityAuthToken, credential_uuid=credentialUuid)

        # Create IAM role in linked account
        create_role(role_name=roleInfo['roleName'],
                    external_id=roleInfo['externalId'],
                    cloudability_account_id=roleInfo['trustedAccountId'],
                    la_credentials=laCredentials)

        # Delete existing IAM keys and Managed policy, if they exist
        delete_old_keys(la_credentials=laCredentials,
                        la_account_id=laAccountId)

        update_account_data(auth_token=cloudabilityAuthToken,
                            la_account_id=laAccountId,
                            account_cc=accountTagCostCenter,
                            account_env=accountTagEnvironment,
                            account_status=accountStatus,
                            account_dept=requestorDepartment,
                            account_division=requestorDivision,
                            account_owner=accountTechnicalContactFullName,
                            account_name=accountTagLongProjectName,
                            account_group_map=cloudabilityAccountGroupMap)

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "CLOUDABILITY",
            "function": "talr-cloudability",
            "message": incomingMessage
        }
    )

    return

def verify_account(auth_token, la_account_id):

    getAccounts = requests.get("https://api.cloudability.com/v3/internal/vendors/accounts/", auth=(auth_token,''))
    print("getAccounts status code:", getAccounts.status_code)

    # Does account have credentials in Cloudability?
    for i in json.loads(getAccounts.content)['result'][0]['children']:
        if la_account_id in i['id']:
            print("account found in list")
            try:
                if i['credential']:
                    pass
            except KeyError as e:
                print(e)
                return {"state" : "no_credentials_found"}
        else:
            pass

    # What credential type exists?
    for i in json.loads(getAccounts.content)['result'][0]['children']:
        if la_account_id in i['id'] and i['credential']:
            print("looking for credential type")
            if i['credential']['credData']['providerType'] == 'AWS_ROLE':
                #print({"state": "aws_role", "credentialId": i['credential']['id']})
                return {"state": "aws_role", "credentialId": i['credential']['id']}
            elif i['credential']['credData']['providerType'] == 'AWS_USER':
                #print({"state": "aws_user", "credentialId": i['credential']['id']})
                return {"state": "aws_user", "credentialId": i['credential']['id']}
        else:
            pass

    return {"state": "no_account_found"}

def create_role(role_name, external_id, cloudability_account_id, la_credentials):

    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    assumeRolePolicy = '{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"AWS": "arn:aws:iam::' + cloudability_account_id + ':user/cloudability"},"Action": "sts:AssumeRole","Condition": {"StringEquals": {"sts:ExternalId": "' + external_id + '"}}}]}'

    try:
        laIam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assumeRolePolicy,
            Description='Used by the Cloudability service to pull usage data.'
        )
    except Exception as e:
        print(e)

    laIam.put_role_policy(
        RoleName=role_name,
        PolicyName='CloudabilityAccess',
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudwatch:GetMetricStatistics","dynamodb:DescribeTable","dynamodb:ListTables","ec2:DescribeImages","ec2:DescribeInstances","ec2:DescribeRegions","ec2:DescribeReservedInstances","ec2:DescribeReservedInstancesModifications","ec2:DescribeSnapshots","ec2:DescribeVolumes","ecs:DescribeClusters","ecs:DescribeContainerInstances","ecs:ListClusters","ecs:ListContainerInstances","elasticache:DescribeCacheClusters","elasticache:DescribeReservedCacheNodes","elasticache:ListTagsForResource","elasticmapreduce:DescribeCluster","elasticmapreduce:ListClusters","elasticmapreduce:ListInstances","rds:DescribeDBClusters","rds:DescribeDBInstances","rds:DescribeReservedDBInstances","rds:ListTagsForResource","redshift:DescribeClusters","redshift:DescribeReservedNodes","redshift:DescribeTags"],"Resource": "*"}]}'
    )

    return

def migrate_to_role(auth_token, credential_id, la_account_id):

    headers = {'content-type': 'application/json'}
    migrateToRole = requests.post("https://api.cloudability.com/v3/internal/credentials/aws/user/" +
                                  credential_id + "/migrate-to-role", auth=(auth_token,''), headers=headers)

    print(migrateToRole.status_code)

    getAccounts = requests.get("https://api.cloudability.com/v3/internal/vendors/accounts/", auth=(auth_token,''))

    roleName = None
    externalId = None
    cloudabilityAccountId = None
    for i in json.loads(getAccounts.content)['result'][0]['children']:
        if la_account_id in i['id']:
            roleName = i['credential']['credData']['providerInfo']['roleName']
            externalId = i['credential']['credData']['providerInfo']['externalId']
            cloudabilityAccountId = i['credential']['credData']['providerInfo']['trustedAccountId']

    return {"roleName": roleName, "externalId": externalId, "trustedAccountId": cloudabilityAccountId}


def create_credentials(auth_token, organization_id, la_account_id):

    headers = {'content-type': 'application/json'}
    requestCredentials = {"organizationId": organization_id, "accountId": la_account_id, "providerInfo": {}}
    credentialsUuid = requests.post("https://api.cloudability.com/v3/internal/credentials/aws/role",
                                       data=json.dumps(requestCredentials),
                                       auth=(auth_token,''),
                                       headers=headers)

    print("Account", la_account_id, "credentials status_code:", credentialsUuid.status_code)
    print("Account", la_account_id, "content:", credentialsUuid.content)

    credentialsInfo = requests.get("https://api.cloudability.com/v3/internal/credentials/aws/role/" +
                                   json.loads(credentialsUuid.content)['result'],
                                       auth=(auth_token,''))

    return json.loads(credentialsInfo.content)['result']['providerInfo']

def check_credentials(auth_token, credential_uuid):

    #print("Account", la_account_id, "credentials status_code:", credentialsUuid.status_code)
    #print("Account", la_account_id, "content:", credentialsUuid.content)

    credentialsInfo = requests.get("https://api.cloudability.com/v3/internal/credentials/aws/role/" + credential_uuid,
                                       auth=(auth_token,''))

    return json.loads(credentialsInfo.content)['result']['providerInfo']

def delete_old_keys(la_credentials, la_account_id):

    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    try:
        laIam.delete_user(
            UserName='cloudability-app'
        )
    except Exception as e:
        print(e)
        print("No cloudability-app IAM user found to delete.")

    try:
        laIam.delete_policy(
            PolicyArn='arn:aws:iam::' + la_account_id + ':policy/ADSKCloudabilityAnalyticsAccess'
        )
    except Exception as e:
        print(e)
        print("No CloudabilityAnalyticsAccess managed policy found to delete.")

    return

def update_account_data(auth_token, la_account_id, account_cc, account_env, account_name, account_owner, account_dept, account_division, account_status, account_group_map):

    cloudabilityAuth = {"auth_token": auth_token}
    headers = {'Content-Type': 'application/json'}
    account_identifier = la_account_id[:4] + '-' + la_account_id[4:8] + '-' + la_account_id[8:]

    getAccountGroupEntries = requests.get("https://app.cloudability.com/api/1/account_group_entries/",
                                          params=cloudabilityAuth)

    for i in json.loads(getAccountGroupEntries.content):
        if account_identifier in i['account_identifier']:
            deleteEntry = requests.delete("https://app.cloudability.com/api/1/account_group_entries/" + str(i['id']),
                                          params=cloudabilityAuth,
                                          headers=headers)
            if deleteEntry.status_code != 200:
                raise Exception({"error": "Non-200 response received from Cloudablity for account entry DELETE"})

    groupEntryValue = None
    for i in account_group_map.items():
        if i[0] == 'accountTagCostCenter':
            groupEntryValue = account_cc
        elif i[0] == 'accountTagEnvironment':
            groupEntryValue = account_env
        elif i[0] == 'accountTagLongProjectName':
            groupEntryValue = account_name
        elif i[0] == 'accountTechnicalContactFullName':
            groupEntryValue = account_owner
        elif i[0] == 'requestorDepartment':
            groupEntryValue = account_dept
        elif i[0] == 'requestorDivision':
            groupEntryValue = account_division
        elif i[0] == 'accountStatus':
            groupEntryValue = account_status

        accountGroupEntryPayload = {"account_group_id": int(i[1]),
                                    "account_identifier": account_identifier,
                                    "value": groupEntryValue}
        #accountGroupEntryPayload = "{\"account_group_id\": 163, \"account_identifier\": \"7070-1110-3192\", \"value\": \"Internal Affairs\"}"

        accountGroupEntryResponse = requests.post("https://app.cloudability.com/api/1/account_group_entries/",
                                                              data=json.dumps(accountGroupEntryPayload),
                                                              params=cloudabilityAuth,
                                                              headers=headers)

        print(accountGroupEntryPayload)
        print(accountGroupEntryResponse.status_code)
        print(accountGroupEntryResponse.content)

        if accountGroupEntryResponse.status_code != 201:
            raise Exception({"error": "Non-201 response received from Cloudablity for account entry POST"})

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
    laIam = boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)
