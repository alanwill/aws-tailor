# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import StringIO
import sys
import time
import zipfile

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
from retry import retry

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
sts = boto3.client('sts')
kinesis = boto3.client('kinesis')
s3 = boto3.client('s3')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    incomingMessage = event['Records'][0]['Sns']['Message'].split('\n')

    # Parse the SNS message with the Cloudformation response. Since it's not in JSON format, it needs to be converted
    # to a dictionary first
    cfnIncomingMessage = {}
    for line in incomingMessage:
        key = line.partition("=")[0]
        value = line.partition("=")[2].lstrip("'").rstrip("'")
        cfnIncomingMessage[key] = value
    print(cfnIncomingMessage)

    # Check each incoming event and determine whether the Stack has completed successfully, only proceed if yes
    # otherwise exit.
    try:
        if "arn:aws:cloudformation:" in cfnIncomingMessage['PhysicalResourceId'] and \
                        cfnIncomingMessage['ResourceStatus'] == "CREATE_COMPLETE" and \
                        cfnIncomingMessage['StackName']:
            global stackId
            stackId = cfnIncomingMessage['StackId']
            global region
            region = stackId.split(":")[3]
            physicalResourceId = cfnIncomingMessage['PhysicalResourceId']
            laAccountId = cfnIncomingMessage['Namespace']
            stackName = cfnIncomingMessage['StackName']
            print("StackId:", stackId)
            print("region:", region)
            print("PhysicalResourceId:", physicalResourceId)
            print("laAccountId:", laAccountId)
            print("StackName", stackName)

            # Scan talr-accountInfo table for requestId
            getRequestId = accountInfo.scan(
                TableName=os.environ['TAILOR_TABLENAME_ACCOUNTINFO'],
                ProjectionExpression='requestId',
                FilterExpression=Attr('accountId').eq(laAccountId)
            )
            global requestId
            requestId = getRequestId['Items'][0]['requestId']
            print("requestId:", requestId)
        else:
            return "VPC not ready."
    except Exception as e:
        print(e)
        print("***VPC not ready.***")
        return "VPC not ready."

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "VPCFLOWLOGS",
            "function": "talr-vpcflowlogs",
            "message": {"accountId": laAccountId, "stackId": stackId}
        }
    )

    # Look up the accountEmailAddress from the known requestId
    getAccountEmailAddress = accountInfo.query(
        IndexName='gsiRequestId',
        KeyConditionExpression=Key('requestId').eq(requestId)
    )
    accountEmailAddress = getAccountEmailAddress['Items'][0]['accountEmailAddress']

    # Lookup accountInfo variables
    getAccountInfo = accountInfo.get_item(
        Key={
            'accountEmailAddress': accountEmailAddress
        }
    )
    laAccountId = getAccountInfo['Item']['accountId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCompanyCode = getCbInfo['Item']['accountCompanyCode']
    accountCbId = getCbInfo['Item']['accountCbId']
    accountCsId = getCbInfo['Item']['accountCsId']
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']
    accountVpcFlowLogsS3Bucket = getCbInfo['Item']['accountVpcFlowLogsS3Bucket']

    # Initialize credentials for core services account
    cs_aws_access_key_id, cs_aws_secret_access_key, cs_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountCsId)

    cs_vpc_flow_logs_infra(cs_aws_access_key_id=cs_aws_access_key_id,
                           cs_aws_secret_access_key=cs_aws_secret_access_key,
                           cs_aws_session_token=cs_aws_session_token,
                           lambda_code_s3bucket=accountTailorConfigBucket,
                           vpcflowlogs_s3bucket=accountVpcFlowLogsS3Bucket,
                           cs_account_id=accountCsId,
                           cb_account_id=accountCbId,
                           company_code=accountCompanyCode,
                           region=region)

    # Initialize credentials for linked account
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=laAccountId)

    # Lookup vpcid
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )
    describeVpcResource = laCfn.describe_stack_resource(
        StackName=stackName,
        LogicalResourceId='VPC'
    )
    try:
        vpcId = describeVpcResource['StackResourceDetail']['PhysicalResourceId']
    except Exception as e:
        print(e)
        print("***No VPC ID found in Cloudformation stack***")
        return

    # Initialize client services for linked account resource creation
    laEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )
    laLogs = boto3.client(
        'logs',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )
    laIam = boto3.client(
        'iam',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    # Create VPC FLow Logs log group and set retention
    logGroupName = '/' + accountIamAlias + '/vpcflowlogs/' + region + '/' + vpcId

    try:
        laLogs.create_log_group(
            logGroupName=logGroupName
        )
    except Exception as e:
        print(e)
        print("There was a problem creating the log group")

    try:
        laLogs.put_retention_policy(
            logGroupName=logGroupName,
            retentionInDays=7
        )
    except Exception as e:
        print(e)
        print("There was a problem setting the log retention")

    # Check the log groups really do exist and are ready
    @retry((ValueError), delay=1, backoff=2, max_delay=30, jitter=2, tries=60)
    def check_for_loggroup():
        describeLogGroup = laLogs.describe_log_groups(
            logGroupNamePrefix=logGroupName
        )
        for i in describeLogGroup['logGroups']:
            if logGroupName in i['logGroupName']:
                return True
            else:
                raise ValueError(logGroupName + ' loggroup not ready yet')

    check_for_loggroup()

    try:
        # Set assume role policy doc for VPC flow logs
        assumeRolePolicyDocumentVpcFlowLogs = '{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Principal": { "Service": "vpc-flow-logs.amazonaws.com" }, "Action": "sts:AssumeRole" }]}'

        # Create IAM role for VPC FLow Logs
        createVpcFlowLogsDeliveryRole = laIam.create_role(
            RoleName=accountCompanyCode.title() + 'VpcFlowLogsDeliveryRole',
            AssumeRolePolicyDocument=assumeRolePolicyDocumentVpcFlowLogs
        )
        createVpcFlowLogsDeliveryPolicy = laIam.create_policy(
            PolicyName=accountCompanyCode.capitalize() + 'VpcFlowLogsDeliveryAccess',
            PolicyDocument='{ "Version": "2012-10-17", "Statement": [{ "Action": ["logs:CreateLogStream", "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:PutLogEvents"], "Effect": "Allow", "Resource": "*" }] }',
            Description='VPC Flow Logs Delivery to Cloudwatch Logs'
        )
        laIam.attach_role_policy(
            RoleName=createVpcFlowLogsDeliveryRole['Role']['RoleName'],
            PolicyArn=createVpcFlowLogsDeliveryPolicy['Policy']['Arn']
        )
    except Exception as e:
        print(e)
        print("Role or policy may already exist")

    print("Checking for flowlog role active state")

    # Check that role really does exist and is in a ready state
    @retry((ValueError), delay=1, backoff=2, max_delay=30, jitter=2, tries=60)
    def check_for_flowlog_role():
        describeRole = laIam.get_role(
            RoleName=accountCompanyCode.title() + 'VpcFlowLogsDeliveryRole'
        )
        if accountCompanyCode.title() + 'VpcFlowLogsDeliveryRole' in describeRole['Role']['RoleName']:
            return True
        else:
            raise ValueError(accountCompanyCode.title() + 'VpcFlowLogsDeliveryRole role not ready yet')

    check_for_flowlog_role()

    # Create VPC Flow Logs
    describeRole = laIam.get_role(
        RoleName=accountCompanyCode.title() + 'VpcFlowLogsDeliveryRole'
    )
    try:
        laEc2.create_flow_logs(
            ResourceIds=[vpcId],
            ResourceType='VPC',
            TrafficType='ALL',
            LogGroupName=logGroupName,
            DeliverLogsPermissionArn=describeRole['Role']['Arn']
        )
    except Exception as e:
        print(e)

    # Create Cloudwatch Logs VPC Flow Logs subscription filter
    laLogs.put_subscription_filter(
        logGroupName=logGroupName,
        filterName='VpcFlowLogsToKinesis',
        filterPattern='[version, account_id, interface_id, srcaddr != "-", dstaddr != "-", srcport != "-", dstport != "-", protocol, packets, bytes, start, end, action, log_status]',
        destinationArn='arn:aws:logs:' + region + ':' + accountCsId + ':destination:vpc-flow-logs'
    )

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "VPCFLOWLOGS",
            "function": "talr-vpcflowlogs",
            "message": {"accountId": laAccountId, "stackId": stackId}
        }
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

    # Initialize IAM client with Linked Account credentials
    boto3.client(
        'iam',
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    return (la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)


def cs_vpc_flow_logs_infra(cs_aws_access_key_id, cs_aws_secret_access_key, cs_aws_session_token, lambda_code_s3bucket,
                           vpcflowlogs_s3bucket, cs_account_id, cb_account_id, region, company_code):
    # ######
    # Create Kinesis stream if it doesn't already exist
    # ######
    csKinesis = boto3.client(
        'kinesis',
        region_name=region,
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token,
    )

    # List streams
    listStreams = csKinesis.list_streams()

    if 'vpc-flow-logs' not in listStreams['StreamNames']:
        csKinesis.create_stream(
            StreamName='vpc-flow-logs',
            ShardCount=1
        )

    # Check that the stream is ready for use
    @retry((ValueError), delay=1, backoff=2, max_delay=30, jitter=2, tries=60)
    def check_for_kinesis_stream():
        describeStream = csKinesis.describe_stream(
            StreamName='vpc-flow-logs',
            Limit=2
        )
        if 'ACTIVE' in describeStream['StreamDescription']['StreamStatus']:
            return True
        else:
            raise ValueError('kinesis stream vpc-flow-logs not ready yet')

    check_for_kinesis_stream()

    # ######
    # Create Cloudwatch Logs Destination if it doesn't already exist
    # ######
    csLogs = boto3.client(
        'logs',
        region_name=region,
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token,
    )

    csIam = boto3.client(
        'iam',
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token,
    )

    # List roles
    listRoles = csIam.list_roles()

    roles = list()
    for role in listRoles['Roles']:
        roles.append(role['RoleName'])

    if company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole' not in roles:
        csIam.create_role(
            RoleName=company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole',
            AssumeRolePolicyDocument='{"Statement": {"Effect": "Allow","Principal": { "Service": ["logs.us-west-1.amazonaws.com","logs.us-west-2.amazonaws.com","logs.us-east-1.amazonaws.com"] },"Action": "sts:AssumeRole"}}'
        )
        csIam.put_role_policy(
            RoleName=company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole',
            PolicyName='CloudwatchLogsToKinesis',
            PolicyDocument='{"Statement": [{"Effect": "Allow","Action": "kinesis:PutRecord","Resource": "arn:aws:kinesis:*:' + cs_account_id + ':stream/vpc-flow-logs"},{"Effect": "Allow","Action": "iam:PassRole","Resource": "arn:aws:iam::' + cs_account_id + ':role/' + company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole"}]}'
        )

    # Check that the role is ready for use
    @retry((ValueError), delay=1, backoff=2, max_delay=30, jitter=2, tries=60)
    def check_for_destination_role():
        describeRole = csIam.get_role(
            RoleName=company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole'
        )
        if company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole' in describeRole['Role']['RoleName']:
            return True
        else:
            raise ValueError(company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole role not ready yet')

    check_for_destination_role()

    # List Destinations
    listDestinations = csLogs.describe_destinations()

    destinations = list()
    for destination in listDestinations['destinations']:
        destinations.append(destination['destinationName'])

    if 'vpc-flow-logs' not in destinations:
        csLogs.put_destination(
            destinationName='vpc-flow-logs',
            targetArn='arn:aws:kinesis:' + region + ':' + cs_account_id + ':stream/vpc-flow-logs',
            roleArn='arn:aws:iam::' + cs_account_id + ':role/' + company_code.title() + 'CloudwatchLogsToKinesisVpcFlowLogsRole'
        )
        csLogs.put_destination_policy(
            destinationName='vpc-flow-logs',
            accessPolicy='{"Version" : "2012-10-17","Statement" : [{"Sid" : "","Effect" : "Allow","Principal" : {"AWS" : "*"},"Action" : "logs:PutSubscriptionFilter","Resource" : "arn:aws:logs:' + region + ':' + cs_account_id + ':destination:vpc-flow-logs"}]}'
        )

    # ######
    # Create Lambda function to process logs from Kinesis stream if it doesn't already exist
    # ######
    csLambda = boto3.client(
        'lambda',
        region_name=region,
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token,
    )
    csIam = boto3.client(
        'iam',
        aws_access_key_id=cs_aws_access_key_id,
        aws_secret_access_key=cs_aws_secret_access_key,
        aws_session_token=cs_aws_session_token,
    )

    # List functions
    listFunctions = csLambda.list_functions()

    # List roles
    listRoles = csIam.list_roles()

    roles = list()
    for role in listRoles['Roles']:
        roles.append(role['RoleName'])

    if 'talr-processor-vpcflowlogs' not in roles:
        csIam.create_role(
            RoleName='talr-processor-vpcflowlogs',
            AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Principal": {"Service": "lambda.amazonaws.com"},"Action": "sts:AssumeRole"}]}'
        )
        csIam.put_role_policy(
            RoleName='talr-processor-vpcflowlogs',
            PolicyName='write-to-s3',
            PolicyDocument='{"Statement": [{"Effect": "Allow","Action": ["s3:ListBucket" ],"Resource": [ "arn:aws:s3:::' + vpcflowlogs_s3bucket + '"]},{"Effect": "Allow","Action": [ "s3:PutObject"],"Resource": [ "arn:aws:s3:::' + vpcflowlogs_s3bucket + '/*"]}]}'
        )
        csIam.attach_role_policy(
            RoleName='talr-processor-vpcflowlogs',
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaKinesisExecutionRole'
        )

    # Check that the role is ready for use
    @retry((ValueError), delay=1, backoff=2, max_delay=30, jitter=2, tries=60)
    def check_for_lambda_role():
        describeRole = csIam.get_role(
            RoleName='talr-processor-vpcflowlogs'
        )
        if 'talr-processor-vpcflowlogs' in describeRole['Role']['RoleName']:
            return True
        else:
            raise ValueError('talr-processor-vpcflowlogs role not ready yet')

    check_for_lambda_role()

    functions = list()
    for function in listFunctions['Functions']:
        functions.append(function['FunctionName'])

    # Download Lambda code and create zip archive
    getLambdaCode = s3.get_object(
        Bucket=lambda_code_s3bucket,
        Key='lambda/talr-processor-vpcflowlogs.py'
    )
    lambdaCode = getLambdaCode['Body'].read()

    lambdaZip = StringIO.StringIO()
    with zipfile.ZipFile(lambdaZip, 'w') as z:
        z.writestr('talr-processor-vpcflowlogs.py', lambdaCode)

    # Create Lambda function
    if 'talr-processor-vpcflowlogs' not in functions:
        csLambda.create_function(
            FunctionName='talr-processor-vpcflowlogs',
            Runtime='python2.7',
            Role='arn:aws:iam::' + cs_account_id + ':role/talr-processor-vpcflowlogs',
            Handler='talr-processor-vpcflowlogs.handler',
            Code={
                'ZipFile': lambdaZip.getvalue()
            },
            Description='Reads from vpc-flow-logs Kinesis Stream and writes to S3 (Deployed and managed by Tailor)',
            Timeout=60,
            MemorySize=256
        )
        csLambda.create_event_source_mapping(
            EventSourceArn='arn:aws:kinesis:' + region + ':' + cs_account_id + ':stream/vpc-flow-logs',
            FunctionName='talr-processor-vpcflowlogs',
            Enabled=True,
            BatchSize=100,
            StartingPosition='LATEST'
        )

    return
