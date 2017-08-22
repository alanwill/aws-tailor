# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from botocore.exceptions import ClientError
import os
import sys
import time
import hashlib

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
from retrying import retry

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
sts = boto3.client('sts')
s3 = boto3.client('s3')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
    accountEmailAddress = incomingMessage['lambda']['accountEmailAddress']

    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    laAccountId = getAccountInfo['Item']['accountId']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    requestId = getAccountInfo['Item']['requestId']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "CONFIG",
            "function": "talr-config",
            "message": incomingMessage
        }
    )

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountConfigS3Bucket = getCbInfo['Item']['accountConfigS3Bucket']
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']
    accountCompanyCode = getCbInfo['Item']['accountCompanyCode']
    accountCbId = getCbInfo['Item']['accountCbId']

    # Payer account credentials
    payerAssumeRole = sts.assume_role(
        RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
        RoleSessionName="talrConfigPayerAssumeRole"
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
        RoleArn="arn:aws:iam::" + laAccountId + ":role/PayerAccountAccessRole",
        RoleSessionName="talrConfigLaAssumeRole"
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

    # Initialize a Session object in order to look up Config regions
    boto3Session = boto3.Session(
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token
    )

    # All Config regions
    configRegions = boto3Session.get_available_regions(
        service_name='config',
        partition_name='aws',
    )

    # Check for ConfigServiceRole IAM role
    try:
        getRole = laIam.get_role(
            RoleName=accountCompanyCode.title() + 'ConfigServiceRole'
        )
        configIamRoleArn = getRole['Role']['Arn']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            createRole = laIam.create_role(
                RoleName=accountCompanyCode.title() + 'ConfigServiceRole',
                AssumeRolePolicyDocument='{ "Version": "2012-10-17", "Statement": [ { "Sid": "", "Effect": "Allow", "Principal": { "Service": "config.amazonaws.com" }, "Action": "sts:AssumeRole" } ]}'
            )
            configIamRoleArn = createRole['Role']['Arn']
        else:
            return e

    # Get ConfigS3Access policy from S3
    getConfigS3AccessFromS3 = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key='iam/managed-policies/' + accountCompanyCode.upper() + 'ConfigS3Access.json'
    )
    configS3AccessPolicy = json.loads(getConfigS3AccessFromS3['Body'].read())
    configS3AccessPolicy['Statement'][0]['Resource'].append("arn:aws:s3:::" + accountConfigS3Bucket + "/*")
    configS3AccessPolicy['Statement'][1]['Resource'].append("arn:aws:s3:::" + accountConfigS3Bucket)

    # Check the correct role and policy exist
    try:
        # Query for Managed Policies
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountCompanyCode.title() + 'ConfigServiceRole'
        )
        # Query for Inline Policies
        listInlinePolicies = laIam.list_role_policies(
            RoleName=accountCompanyCode.title() + 'ConfigServiceRole'
        )
        if len(listRolePolicies['AttachedPolicies']) == 0:
            recreate_config_service_role_policies(config_s3_access_policy=configS3AccessPolicy,
                                                  iam_client=laIam,
                                                  company_code=accountCompanyCode)
        elif len(listInlinePolicies['PolicyNames']) > 0:
            recreate_config_service_role_policies(config_s3_access_policy=configS3AccessPolicy,
                                                  iam_client=laIam,
                                                  company_code=accountCompanyCode)
        else:
            for i in listRolePolicies['AttachedPolicies']:
                if i['PolicyName'] == accountCompanyCode.capitalize() + 'ConfigS3Access' or i['PolicyName'] == 'AWSConfigRole':
                    getS3Policy = laIam.get_policy(
                        PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'ConfigS3Access'
                    )
                    defaultVersionId = getS3Policy['Policy']['DefaultVersionId']
                    getPolicyVersion = laIam.get_policy_version(
                        PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'ConfigS3Access',
                        VersionId=defaultVersionId
                    )
                    foundS3PolicyDocument = getPolicyVersion['PolicyVersion']['Document']

                    if hashlib.sha256(str(foundS3PolicyDocument)).hexdigest() == \
                            hashlib.sha256(str(configS3AccessPolicy)).hexdigest():
                        print("Checksums match")
                        continue
                    else:
                        recreate_config_service_role_policies(config_s3_access_policy=configS3AccessPolicy,
                                                              iam_client=laIam,
                                                              company_code=accountCompanyCode)

                else:
                    recreate_config_service_role_policies(config_s3_access_policy=configS3AccessPolicy,
                                                          iam_client=laIam,
                                                          company_code=accountCompanyCode)
    except Exception as e:
        print(e)
        recreate_config_service_role_policies(config_s3_access_policy=configS3AccessPolicy,
                                              iam_client=laIam,
                                              company_code=accountCompanyCode)

    # Function that configures the Config service in all but us-east-1
    def setupConfig(region):
        # Initialize Config client with Linked Account credentials
        laConfig = boto3.client(
            'config',
            aws_access_key_id=la_aws_access_key_id,
            aws_secret_access_key=la_aws_secret_access_key,
            aws_session_token=la_aws_session_token,
            region_name=region
        )

        # Create Config recorder
        if region != "us-east-1":
            laConfig.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': 'default',
                    'roleARN': configIamRoleArn,
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResourceTypes': False
                    }
                }
            )
        else:
            laConfig.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': 'default',
                    'roleARN': configIamRoleArn,
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResourceTypes': True
                    }
                }
            )

        @retry(wait_exponential_multiplier=1000, wait_exponential_max=2000, stop_max_delay=30000)
        def createDeliveryChannel():
            laConfig.put_delivery_channel(
                DeliveryChannel={
                    'name': 'default',
                    's3BucketName': accountConfigS3Bucket,
                    's3KeyPrefix': accountIamAlias,
                    'configSnapshotDeliveryProperties': {
                        'deliveryFrequency': 'One_Hour'
                    }
                }
            )

        createDeliveryChannel()

        laConfig.start_configuration_recorder(
            ConfigurationRecorderName='default'
        )

        describeConfigRecorder = laConfig.describe_configuration_recorder_status()
        print(describeConfigRecorder)

    # Loop through each region and launch a thread to configure service in parallel for each
    for region in configRegions:
        #t = Thread(target=setupConfig, args=(region,))
        #t.start()
        setupConfig(region)

        # config_rules(account_company_code=accountCompanyCode,
        #              account_id=accountId,
        #              region=region,
        #              la_aws_access_key_id=la_aws_access_key_id,
        #              la_aws_secret_access_key=la_aws_secret_access_key,
        #              la_aws_session_token=la_aws_session_token)

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "CONFIG",
            "function": "talr-config",
            "message": incomingMessage
        }
    )

    return


def recreate_config_service_role_policies(config_s3_access_policy, iam_client, company_code):

    # Delete any managed policies attached to role
    listRolePolicies = iam_client.list_attached_role_policies(
        RoleName=company_code.title() + 'ConfigServiceRole'
    )
    for i in listRolePolicies['AttachedPolicies']:
        iam_client.detach_role_policy(
            RoleName=company_code.title() + 'ConfigServiceRole',
            PolicyArn=i['PolicyArn']
        )
        # Delete policy if it's not an AWS Managed Policy (as opposed to Customer Managed Policy)
        if not i['PolicyArn'].startswith('arn:aws:iam::aws:'):
            listPolicyVersions = iam_client.list_policy_versions(
                PolicyArn=i['PolicyArn']
            )
            for ii in listPolicyVersions['Versions']:
                if ii['IsDefaultVersion'] is False:
                    iam_client.delete_policy_version(
                        PolicyArn=i['PolicyArn'],
                        VersionId=ii['VersionId']
                    )
            iam_client.delete_policy(
                PolicyArn=i['PolicyArn']
            )

    # Delete any inline policies attached to role
    listInlinePolicies = iam_client.list_role_policies(
        RoleName=company_code.title() + 'ConfigServiceRole'
    )
    for i in listInlinePolicies['PolicyNames']:
        iam_client.delete_role_policy(
            RoleName=company_code.title() + 'ConfigServiceRole',
            PolicyName=i
        )

    print(config_s3_access_policy)
    # Create policy
    createConfigS3Policy = iam_client.create_policy(
        PolicyName=company_code.capitalize() + 'ConfigS3Access',
        PolicyDocument=json.dumps(config_s3_access_policy),
        Description='Grants AWS Config write access to S3 bucket'
    )
    configS3AccessPolicyArn = createConfigS3Policy['Policy']['Arn']

    iam_client.attach_role_policy(
        RoleName=company_code.title() + 'ConfigServiceRole',
        PolicyArn='arn:aws:iam::aws:policy/service-role/AWSConfigRole'
    )
    iam_client.attach_role_policy(
        RoleName=company_code.title() + 'ConfigServiceRole',
        PolicyArn=configS3AccessPolicyArn
    )
    return


def config_rules(account_company_code, account_id, region, la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token, config_s3_bucket):

    laConfig = boto3.client(
        'config',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
        region_name=region
    )

    def create_rule_cloutrail_enabled(config_client, account_company_code, config_s3_bucket):
        # Config Rule - Cloudtrail Enabled
        createRuleCloutrailEnabled = laConfig.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'CloudtrailEnabled',
                'Description': 'Checks that Cloudtrail is enabled in every region',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'CLOUD_TRAIL_ENABLED',
                },
                'InputParameters': '{ "s3BucketName": ' + config_s3_bucket + '}',
                'MaximumExecutionFrequency': 'One_Hour',
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_root_mfa_enabled(config_client, account_company_code):
        # Config Rule - Root MFA Enabled
        createRuleRootMfaEnabled = laConfig.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'RootMfaEnabled',
                'Description': 'Checks that root MFA is enabled',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'ROOT_ACCOUNT_MFA_ENABLED',
                },
                'MaximumExecutionFrequency': 'One_Hour',
                'ConfigRuleState': 'ACTIVE'
            }
        )

        create_rule_desired_instance_tenancy(config_client=laConfig, account_company_code=account_company_code)

    def create_rule_desired_instance_tenancy(config_client, account_company_code):
        # Config Rule - Desired Instance Tenancy
        createRuleDesiredInstanceTenancy = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'DesiredInstanceTenancy',
                'Description': 'Checks whether an instance has been launched with Dedicated tenancy',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'DESIRED_INSTANCE_TENANCY',
                },
                'InputParameters': '{ "tenancy": "DEFAULT"}',
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_desired_ec2_instance_in_vpc(config_client, account_company_code):
        # Config Rule - EC2 Instance in VPC
        createRuleDesiredEc2InstanceInVpc = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'Ec2InstanceInVpc',
                'Description': 'Checks that an EC2 instance is in a VPC',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'INSTANCES_IN_VPC',
                },
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_desired_eip_attached(config_client, account_company_code):
        # Config Rule - EIP Attached
        createRuleDesiredEipAttached = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'EipAttached',
                'Description': 'Checks that all EIPs are attached to an ENI',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'EIP_ATTACHED',
                },
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_desired_iam_password_policy(config_client, account_company_code):
        # Config Rule - IAM Password Policy
        createRuleDesiredIamPasswordPolicy = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'IamPasswordPolicy',
                'Description': 'Checks IAM password policy meets requirements',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'IAM_PASSWORD_POLICY',
                },
                'InputParameters': '{ "RequireUppercaseCharacters": "True", '
                                   '"RequireLowercaseCharacters": "True", '
                                   '"RequireSymbols": "True", '
                                   '"RequireNumbers": "True", '
                                   '"MinimumPasswordLength": "8", '
                                   '"PasswordReusePrevention": "6", '
                                   '"MaxPasswordAge": "90" }',
                'MaximumExecutionFrequency': 'One_Hour',
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_restricted_ssh(config_client, account_company_code):
        # Config Rule - Restricted SSH
        createRuleRestrictedSsh = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'RestrictedSsh',
                'Description': 'Checks that incoming SSH access in security groups is restricted',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'INCOMING_SSH_DISABLED',
                },
                'ConfigRuleState': 'ACTIVE'
            }
        )

    def create_rule_ec2_not_in_public_subnet(config_client, account_company_code, account_id, region):
        # Config Rule - EC2 instances not in Public Subnets
        createRuleEc2NotInPublicSubnet = config_client.put_config_rule(
            ConfigRule={
                'ConfigRuleName': account_company_code.capitalize() + 'Ec2NotInPublicSubnet',
                'Description': 'Checks that there are no EC2 instances in public subnets',
                'Scope': {
                    'ComplianceResourceTypes': [
                        'AWS::EC2::Instance',
                    ],
                },
                'Source': {
                    'Owner': 'CUSTOM_LAMBDA',
                    'SourceIdentifier': 'arn:aws:lambda:' + region + ':' + account_id + ':function:talr-configrule-ec2notinpublicsubnet',
                    'SourceDetails': [
                        {
                            'EventSource': 'aws.config',
                            'MessageType': 'ConfigurationItemChangeNotification',
                        },
                    ]
                },
                'ConfigRuleState': 'ACTIVE'
            }
        )

    if region == 'us-east-1':
        create_rule_cloutrail_enabled(config_client=laConfig, account_company_code=account_company_code)
        create_rule_root_mfa_enabled(config_client=laConfig, account_company_code=account_company_code)
        create_rule_desired_iam_password_policy(config_client=laConfig, account_company_code=account_company_code)

        create_rule_desired_instance_tenancy(config_client=laConfig, account_company_code=account_company_code)
        create_rule_desired_ec2_instance_in_vpc(config_client=laConfig, account_company_code=account_company_code)
        create_rule_desired_eip_attached(config_client=laConfig, account_company_code=account_company_code)
        create_rule_restricted_ssh(config_client=laConfig, account_company_code=account_company_code)
        create_rule_ec2_not_in_public_subnet(config_client=laConfig, account_company_code=account_company_code, account_id=account_id, region=region)

    elif region != 'us-east-1' and region != 'ca-central-1' and region != 'sa-east-1' and region != 'ap-south-1':
        create_rule_desired_instance_tenancy(config_client=laConfig, account_company_code=account_company_code)
        create_rule_desired_ec2_instance_in_vpc(config_client=laConfig, account_company_code=account_company_code)
        create_rule_desired_eip_attached(config_client=laConfig, account_company_code=account_company_code)
        create_rule_restricted_ssh(config_client=laConfig, account_company_code=account_company_code)
        create_rule_ec2_not_in_public_subnet(config_client=laConfig, account_company_code=account_company_code, account_id=account_id, region=region)


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
