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
s3 = boto3.client('s3')
sts = boto3.client('sts')


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
    requestId = getAccountInfo['Item']['requestId']
    accountTagShortProjectName = getAccountInfo['Item']['accountTagShortProjectName']
    accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "IAM",
            "function": "talr-iam",
            "message": incomingMessage
        }
    )

    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCompanyCode = getCbInfo['Item']['accountCompanyCode']
    accountCbId = getCbInfo['Item']['accountCbId']
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']

    # Payer account credentials
    payerAssumeRole = sts.assume_role(
        RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
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
        RoleArn="arn:aws:iam::" + laAccountId + ":role/PayerAccountAccessRole",
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

    # Set role names
    accountAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Account-Admins'
    accountReadOnlyRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Account-ReadOnly'
    applicationAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Application-Admins'
    applicationAdminsPlusRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Application-AdminsPlus'
    databaseAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Database-Admins'
    networkAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Network-Admins'
    securityAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Security-Admins'
    serverAdminsRoleName = accountTagShortProjectName + '-' + accountTagEnvironment + '-Server-Admins'

    # Set assume role policy doc for all SAML roles
    assumeRolePolicyDocumentSaml = '{ "Version": "2012-10-17", "Statement": [ { "Sid": "", "Effect": "Allow", "Principal": { "Federated": "arn:aws:iam::' + laAccountId + ':saml-provider/' + accountCompanyCode + '-saml" }, "Action": "sts:AssumeRoleWithSAML", "Condition": { "StringEquals": { "SAML:aud": "https://signin.aws.amazon.com/saml" }}}]}'

    # Clean up resources
    try:
        laIam.delete_saml_provider(
            SAMLProviderArn='arn:aws:iam::' + laAccountId + ':saml-provider/' + accountCompanyCode + '-saml'
        )
    except Exception as e:
        print(e)
        print("No SAML provider to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=accountAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=accountAdminsRoleName
        )
    except Exception as e:
        print(e)
        print("No AccountAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountReadOnlyRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=accountReadOnlyRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=accountReadOnlyRoleName
        )
    except Exception as e:
        print(e)
        print("No AccountReadOnly role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=applicationAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=applicationAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=applicationAdminsRoleName
        )
        laIam.delete_policy(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'ApplicationAdminDeny'
        )
        laIam.delete_policy(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'ApplicationAdminIamAllow'
        )
    except Exception as e:
        print(e)
        print("No ApplicationAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=databaseAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=databaseAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=databaseAdminsRoleName
        )
        laIam.delete_policy(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'DatabaseAdminDeny'
        )
    except Exception as e:
        print(e)
        print("No DatabaseAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=networkAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=networkAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=networkAdminsRoleName
        )
    except Exception as e:
        print(e)
        print("No NetworkAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=securityAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=securityAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=securityAdminsRoleName
        )
    except Exception as e:
        print(e)
        print("No SecurityAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=serverAdminsRoleName
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=serverAdminsRoleName,
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=serverAdminsRoleName
        )
        laIam.delete_policy(
            PolicyArn='arn:aws:iam::' + laAccountId + ':policy/' + accountCompanyCode.capitalize() + 'ServerAdminDeny'
        )
    except Exception as e:
        print(e)
        print("No ServerAdmins role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountCompanyCode.title() + "LambdaBasicExecutionRole"
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=accountCompanyCode.title() + "LambdaBasicExecutionRole",
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=accountCompanyCode.title() + "LambdaBasicExecutionRole"
        )
    except Exception as e:
        print(e)
        print("No " + accountCompanyCode.title() + "LambdaBasicExecutionRole role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountCompanyCode.title() + "LambdaVpcAccessExecutionRole"
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=accountCompanyCode.title() + "LambdaVpcAccessExecutionRole",
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=accountCompanyCode.title() + "LambdaVpcAccessExecutionRole"
        )
    except Exception as e:
        print(e)
        print("No " + accountCompanyCode.title() + "LambdaVpcAccessExecutionRole role to delete")

    try:
        listRolePolicies = laIam.list_attached_role_policies(
            RoleName=accountCompanyCode.title() + "EcsInstanceRole"
        )
        for i in listRolePolicies['AttachedPolicies']:
            laIam.detach_role_policy(
                RoleName=accountCompanyCode.title() + "EcsInstanceRole",
                PolicyArn=i['PolicyArn']
            )
        laIam.delete_role(
            RoleName=accountCompanyCode.title() + "EcsInstanceRole"
        )
    except Exception as e:
        print(e)
        print("No " + accountCompanyCode.title() + "EcsInstanceRole role to delete")

    # Create SAML provider
    getSamlMetadataFile = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key='iam/saml-provider/AWS_PRD_IdP_Metadata.xml'
    )
    samlMetadataFile = getSamlMetadataFile['Body'].read()

    createSamlProvider = laIam.create_saml_provider(
        SAMLMetadataDocument=samlMetadataFile,
        Name=accountCompanyCode + '-saml'
    )
    samlArn = createSamlProvider['SAMLProviderArn']

    # Create SAML IAM Role and policies for Account Admins
    createSamlRoleAccountAdmins = laIam.create_role(
        RoleName=accountAdminsRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleAccountAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )

    # Create SAML IAM Role and policies for Account ReadOnly
    createSamlRoleAccountReadOnly = laIam.create_role(
        RoleName=accountReadOnlyRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleAccountReadOnly['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )

    # Create SAML IAM Role and policies for Application Admins
    createSamlRoleApplicationAdmins = laIam.create_role(
        RoleName=applicationAdminsRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/PowerUserAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )
    getApplicationAdminDenyPolicy = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key='iam/managed-policies/' + accountCompanyCode.capitalize() + 'ApplicationAdminDeny.json'
    )
    applicationAdminDenyPolicy = getApplicationAdminDenyPolicy['Body'].read()

    createApplicationAdminDenyPolicy = laIam.create_policy(
        PolicyName=accountCompanyCode.capitalize() + 'ApplicationAdminDeny',
        PolicyDocument=applicationAdminDenyPolicy,
        Description='Application Admin Deny Policy'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdmins['Role']['RoleName'],
        PolicyArn=createApplicationAdminDenyPolicy['Policy']['Arn']
    )
    getApplicationAdminIamAllowPolicy = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key='iam/managed-policies/' + accountCompanyCode.capitalize() + 'ApplicationAdminIamAllow.json'
    )
    applicationAdminIamAllowPolicy = getApplicationAdminIamAllowPolicy['Body'].read()

    createApplicationAdminIamAllowPolicy = laIam.create_policy(
        PolicyName=accountCompanyCode.capitalize() + 'ApplicationAdminIamAllow',
        PolicyDocument=applicationAdminIamAllowPolicy,
        Description='Application Admin IAM Allow Policy'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdmins['Role']['RoleName'],
        PolicyArn=createApplicationAdminIamAllowPolicy['Policy']['Arn']
    )

    # Create SAML IAM Role and policies for Database Admins
    createSamlRoleDatabaseAdmins = laIam.create_role(
        RoleName=databaseAdminsRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AmazonRDSFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AmazonRedshiftFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/CloudWatchFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AWSLambdaFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )
    getDatabaseAdminDenyPolicy = s3.get_object(
        Bucket=accountTailorConfigBucket,
        Key='iam/managed-policies/' + accountCompanyCode.capitalize() + 'DatabaseAdminDeny.json'
    )
    databaseAdminDenyPolicy = getDatabaseAdminDenyPolicy['Body'].read()

    createDatabaseAdminDenyPolicy = laIam.create_policy(
        PolicyName=accountCompanyCode.capitalize() + 'DatabaseAdminDeny',
        PolicyDocument=databaseAdminDenyPolicy,
        Description='Database Admin Deny Policy'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleDatabaseAdmins['Role']['RoleName'],
        PolicyArn=createDatabaseAdminDenyPolicy['Policy']['Arn']
    )

    # Create SAML IAM Role and policies for Network Admins
    createSamlRoleNetworkAdmins = laIam.create_role(
        RoleName=networkAdminsRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleNetworkAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AmazonVPCFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleNetworkAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AWSDirectConnectFullAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleNetworkAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )

    # Create SAML IAM Role and policies for Security Admins
    createSamlRoleSecurityAdmins = laIam.create_role(
        RoleName=securityAdminsRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleSecurityAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/SecurityAudit'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleSecurityAdmins['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
    )

    # Create SAML IAM Role and policies for Application Admins Plus
    createSamlRoleApplicationAdminsPlus = laIam.create_role(
        RoleName=applicationAdminsPlusRoleName,
        AssumeRolePolicyDocument=assumeRolePolicyDocumentSaml
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdminsPlus['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    laIam.attach_role_policy(
        RoleName=createSamlRoleApplicationAdminsPlus['Role']['RoleName'],
        PolicyArn=createApplicationAdminDenyPolicy['Policy']['Arn']
    )

    # Set assume role policy doc for Lambda Basic Execution Role
    assumeRolePolicyDocumentLambda = '{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Principal": { "Service": "lambda.amazonaws.com" }, "Action": "sts:AssumeRole" }]}'

    # Create Lambda Basic Execution Role
    createLambdaBasicExecutionRole = laIam.create_role(
        RoleName=accountCompanyCode.title() + "LambdaBasicExecutionRole",
        AssumeRolePolicyDocument=assumeRolePolicyDocumentLambda
    )
    laIam.attach_role_policy(
        RoleName=createLambdaBasicExecutionRole['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    )

    # Create Lambda VPC Access Execution Role
    createLambdaVpcAccessExecutionRole = laIam.create_role(
        RoleName=accountCompanyCode.title() + "LambdaVpcAccessExecutionRole",
        AssumeRolePolicyDocument=assumeRolePolicyDocumentLambda
    )
    laIam.attach_role_policy(
        RoleName=createLambdaVpcAccessExecutionRole['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole'
    )

    # Set assume role policy doc for ECS Service Instance Role
    assumeRolePolicyDocumentEcs = '{ "Version": "2008-10-17", "Statement": [{ "Sid": "", "Effect": "Allow", "Principal": { "Service": "ec2.amazonaws.com" }, "Action": "sts:AssumeRole" }]}'

    # Create ECS EC2 Service role
    createEcsServiceInstanceRole = laIam.create_role(
        RoleName=accountCompanyCode.title() + "EcsInstanceRole",
        AssumeRolePolicyDocument=assumeRolePolicyDocumentEcs
    )
    laIam.attach_role_policy(
        RoleName=createEcsServiceInstanceRole['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role'
    )

    # Set assume role policy document for Cfn Administratior Execution Role
    assumeRolePolicyDocumentCloudformation = '{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Principal": { "Service": "cloudformation.amazonaws.com" }, "Action": "sts:AssumeRole" }]}'

    # Create Cloudformation administrator access execution role
    createCfnAdministratorAccessExecutionRole = laIam.create_role(
        RoleName=accountCompanyCode.title() + "CfnAdministratorAccessExecutionRole",
        AssumeRolePolicyDocument=assumeRolePolicyDocumentCloudformation
    )
    laIam.attach_role_policy(
        RoleName=createCfnAdministratorAccessExecutionRole['Role']['RoleName'],
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )

    # Set IAM account password policy
    laIam.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=6,
        HardExpiry=False
    )

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "IAM",
            "function": "talr-iam",
            "message": incomingMessage
        }
    )

    return
