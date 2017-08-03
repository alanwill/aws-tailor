# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
import os
import sys
import time
from base64 import b64decode

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import pynipap
from pynipap import VRF, Pool, Prefix
from netaddr import IPNetwork, cidr_merge, cidr_exclude

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
cloudformation = boto3.client('cloudformation')
kms = boto3.client('kms')
s3 = boto3.client('s3')
sts = boto3.client('sts')


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

    # Check each incoming event and determine whether the Stack has completed successfully, only proceed if yes
    # otherwise exit.
    try:
        if "arn:aws:cloudformation:" in cfnIncomingMessage['PhysicalResourceId'] and \
                        cfnIncomingMessage['ResourceStatus'] == "CREATE_COMPLETE":
            stackId = cfnIncomingMessage['StackId']
            print(stackId)
            describeStack = cloudformation.describe_stacks(
                StackName=stackId
            )
            for i in describeStack['Stacks'][0]['Outputs']:
                if i['OutputKey'] == "TailorRequestId":
                    global requestId
                    requestId = i['OutputValue']
                elif i['OutputKey'] == "NipapDaemonIp":
                    global nipapDeamonIp
                    nipapDeamonIp = i['OutputValue']
                else:
                    continue
        else:
            return "NipapDaemonInstance not ready."
    except Exception as e:
        print(e)
        print("***NipapDaemonInstance not ready.***")
        return "NipapDaemonInstance not ready."

    # Update task start status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "VPC",
            "function": "talr-vpc",
            "message": "none"
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
    accountId = getAccountInfo['Item']['accountId']
    accountCbAlias = getAccountInfo['Item']['accountCbAlias']
    accountIamAlias = getAccountInfo['Item']['accountIamAlias']
    accountTagShortProjectName = getAccountInfo['Item']['accountTagShortProjectName']
    accountTagEnvironment = getAccountInfo['Item']['accountTagEnvironment']
    accountRegion = getAccountInfo['Item']['accountRegion']
    accountVpcAzCount = getAccountInfo['Item']['accountVpcAzCount']
    accountVpcPrefix = getAccountInfo['Item']['accountVpcPrefix']

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCompanyName = getCbInfo['Item']['accountCompanyName']
    accountCbId = getCbInfo['Item']['accountCbId']
    accountTailorConfigBucket = getCbInfo['Item']['accountTailorConfigBucket']
    accountVpcMasterNetworks = getCbInfo['Item']['accountVpcMasterNetworks']
    accountVpc2AzCfnTemplateObjectKey = getCbInfo['Item']['accountVpc2AzCfnTemplateObjectKey']
    accountVpc3AzCfnTemplateObjectKey = getCbInfo['Item']['accountVpc3AzCfnTemplateObjectKey']

    # Initialize credentials for linked account
    la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token = \
        initialize_la_services(account_cb_id=accountCbId, la_account_id=accountId)

    print("accountRegion:", accountRegion)

    # Check if CFN core stack already exists
    for region in accountRegion:
        print("region:", region)

        checkCoreCfn = check_for_core(region, la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token)
        print("checkCoreCfn:", checkCoreCfn)

        if checkCoreCfn is False:

            # Look up named IP pool based on requested region
            vpcMasterNetwork = lookup_vpc_master_network(accountVpcMasterNetworks, region)

            # Sleep for 60 seconds to ensure daemon instance is ready
            time.sleep(90)

            # Call the freeprefix function and get VPC CIDR
            vpcCidr = freeprefix(nipap_deamon_ip=nipapDeamonIp, account_cb_alias=accountCbAlias,
                                 account_iam_alias=accountIamAlias, vpc_network=vpcMasterNetwork,
                                 vpc_prefix=accountVpcPrefix.lstrip('/'))

            # Write vpcCidr to talr-accountInfo table
            putVpcCidr = accountInfo.update_item(
                Key={
                    'accountEmailAddress': accountEmailAddress,
                },
                UpdateExpression='SET #accountVpcCidr.#accountRegion = :val1',
                ExpressionAttributeNames={'#accountVpcCidr': 'accountVpcCidr',
                                          '#accountRegion': region},
                ExpressionAttributeValues={':val1': vpcCidr}
            )

            if accountVpcPrefix == "/24" and accountVpcAzCount == "2":
                accountVpcCfnTemplateObjectKey = accountVpc2AzCfnTemplateObjectKey
                ip = IPNetwork(vpcCidr)
                network28s = list(ip.subnet(28, count=16))
                presentation1 = list(network28s[0:1])
                presentation2 = list(network28s[1:2])
                database1 = list(network28s[2:3])
                database2 = list(network28s[3:4])
                internetlb1 = cidr_merge(list(network28s[4:6]))
                internetlb2 = cidr_merge(list(network28s[6:8]))
                internallb1 = cidr_merge(list(network28s[8:10]))
                internallb2 = cidr_merge(list(network28s[10:12]))
                application1 = cidr_merge(list(network28s[12:14]))
                application2 = cidr_merge(list(network28s[14:16]))

                createVpc = createvpc(request_id=requestId,
                                      region=region,
                                      az_count=accountVpcAzCount,
                                      template_object_key=accountVpcCfnTemplateObjectKey,
                                      template_bucket=accountTailorConfigBucket,
                                      cidr=vpcCidr,
                                      presentation_cidr1=str(presentation1[0]),
                                      presentation_cidr2=str(presentation2[0]),
                                      application_cidr1=str(application1[0]),
                                      application_cidr2=str(application2[0]),
                                      database_cidr1=str(database1[0]),
                                      database_cidr2=str(database2[0]),
                                      internetlb_cidr1=str(internetlb1[0]),
                                      internetlb_cidr2=str(internetlb2[0]),
                                      internallb_cidr1=str(internallb1[0]),
                                      internallb_cidr2=str(internallb2[0]),
                                      app_name=accountTagShortProjectName,
                                      env_name=accountTagEnvironment,
                                      la_aws_access_key_id=la_aws_access_key_id,
                                      la_aws_secret_access_key=la_aws_secret_access_key,
                                      la_aws_session_token=la_aws_session_token)

                print("createVpc:", createVpc)

    # Delete all Default VPCs in all regions
    delete_default_vpcs(la_aws_access_key_id=la_aws_access_key_id,
                        la_aws_secret_access_key=la_aws_secret_access_key,
                        la_aws_session_token=la_aws_session_token)

    delete_nipap_daemon_stack(cfnIncomingMessage['StackName'])

    # Update task end status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "VPC",
            "function": "talr-vpc",
            "message": "none"
        }
    )

    return


def lookup_vpc_master_network(vpc_master_network_pool, account_region):
    # Look up named IP pool based on requested region
    for i in vpc_master_network_pool:
        if i == account_region:
            vpcMasterNetwork = vpc_master_network_pool.get(i)
            return vpcMasterNetwork


def freeprefix(nipap_deamon_ip, account_cb_alias, account_iam_alias, vpc_network, vpc_prefix):
    # Lookup nipap daemon password cipher
    nipapCfn = dynamodb.Table(os.environ['TAILOR_TABLENAME_NIPAPCFN'])
    getNipapCfn = nipapCfn.get_item(
        Key={
            'nipapAlias': account_cb_alias
        }
    )

    # Decrypt nipap daemon password
    nipapDaemonPasswordCipherBlob = getNipapCfn['Item']['nipapDaemonPasswordCipherBlob']
    nipapDeamonPassword = bytes(kms.decrypt(CiphertextBlob=b64decode(nipapDaemonPasswordCipherBlob))['Plaintext'])

    # Look up free CIDR block
    pynipap.xmlrpc_uri = "http://tailor:" + nipapDeamonPassword.rstrip() + "@" + nipap_deamon_ip + ":1337"

    a = pynipap.AuthOptions({
        'authoritative_source': 'tailor_nipap_client'
    })

    # Allocate first available
    new_prefix = Prefix()
    new_prefix.description = account_iam_alias
    new_prefix.type = "assignment"

    # Save will communicate with the backend and ask for the next available desired prefix size
    new_prefix.save({'from-prefix': [vpc_network], 'prefix_length': vpc_prefix})

    # Read the assigned prefix from the new_prefix object
    print("VPC Cidr is: ", new_prefix.prefix)
    return new_prefix.prefix


def createvpc(request_id, region, az_count, template_bucket, template_object_key, cidr, presentation_cidr1,
              presentation_cidr2, application_cidr1, application_cidr2, database_cidr1, database_cidr2,
              internetlb_cidr1, internetlb_cidr2, internallb_cidr1, internallb_cidr2, app_name, env_name,
              la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token):
    # Initialize Cloudformation client with Linked Account credentials
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    # Check if an existing core template exists, if so exit, otherwise create stack
    describeStack = laCfn.describe_stacks()
    if "core" in describeStack['Stacks']:
        print("core stack found, no need to create stack")
        return {"error": "core stack found, no need to create stack"}

    # CFN can only use an SNS topic in the same region as the stack, this determines the correct topic based
    # on the region
    if region == "us-east-1":
        topicName = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[5]
        accountNumber = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[4]
        cfnNotificationArn = "arn:aws:sns:" + region + ":" + accountNumber + ":" + topicName
    elif region == "us-west-1":
        topicName = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[5]
        accountNumber = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[4]
        cfnNotificationArn = "arn:aws:sns:" + region + ":" + accountNumber + ":" + topicName
    elif region == "us-west-2":
        topicName = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[5]
        accountNumber = os.environ['TAILOR_SNSARN_VPCCFN_RESPONSE'].split(":")[4]
        cfnNotificationArn = "arn:aws:sns:" + region + ":" + accountNumber + ":" + topicName

    # Download CFN template from S3 and pass contents to function to be used in Linked Account.
    getCfnTemplate = s3.get_object(
        Bucket=template_bucket,
        Key=template_object_key
    )
    templateBody = getCfnTemplate['Body'].read()

    print("About to create stack in ", region)
    createVpcStack = laCfn.create_stack(
        StackName='core',
        TemplateBody=templateBody,
        Parameters=[
            {
                'ParameterKey': 'CorporateCidrIp',
                'ParameterValue': '10.0.0.0/8'
            },
            {
                'ParameterKey': 'VPCCidr',
                'ParameterValue': cidr
            },
            {
                'ParameterKey': 'PresentationSubnetCidrAZ1',
                'ParameterValue': presentation_cidr1
            },
            {
                'ParameterKey': 'PresentationSubnetCidrAZ2',
                'ParameterValue': presentation_cidr2
            },
            {
                'ParameterKey': 'ApplicationSubnetCidrAZ1',
                'ParameterValue': application_cidr1
            },
            {
                'ParameterKey': 'ApplicationSubnetCidrAZ2',
                'ParameterValue': application_cidr2
            },
            {
                'ParameterKey': 'DatabaseSubnetCidrAZ1',
                'ParameterValue': database_cidr1
            },
            {
                'ParameterKey': 'DatabaseSubnetCidrAZ2',
                'ParameterValue': database_cidr2
            },
            {
                'ParameterKey': 'InternetLoadBalancerSubnetCidrAZ1',
                'ParameterValue': internetlb_cidr1
            },
            {
                'ParameterKey': 'InternetLoadBalancerSubnetCidrAZ2',
                'ParameterValue': internetlb_cidr2
            },
            {
                'ParameterKey': 'InternalLoadBalancerSubnetCidrAZ1',
                'ParameterValue': internallb_cidr1
            },
            {
                'ParameterKey': 'InternalLoadBalancerSubnetCidrAZ2',
                'ParameterValue': internallb_cidr2
            },
            {
                'ParameterKey': 'AppName',
                'ParameterValue': app_name
            },
            {
                'ParameterKey': 'EnvironmentName',
                'ParameterValue': env_name
            }
        ],
        TimeoutInMinutes=15,
        NotificationARNs=[
            cfnNotificationArn,
        ],
        OnFailure='ROLLBACK'
    )
    print(createVpcStack)
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


def delete_default_vpcs(la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token):
    # Initialize a Session object in order to look up EC2 regions
    boto3Session = boto3.Session(
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token
    )
    ec2Regions = boto3Session.get_available_regions(
        service_name='ec2',
        partition_name='aws',
    )

    try:
        for region in ec2Regions:

            # Initialize EC2 boto client in given region
            laEc2Region = boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=la_aws_access_key_id,
                aws_secret_access_key=la_aws_secret_access_key,
                aws_session_token=la_aws_session_token,
            )

            # Describe default VPC in given region
            describeVpcs = laEc2Region.describe_vpcs(
                Filters=[
                    {
                        'Name': 'isDefault',
                        'Values': ['true']
                    }
                ]
            )

            # Describe subnets in default VPC for the given region
            describeSubnets = laEc2Region.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [describeVpcs['Vpcs'][0]['VpcId']]
                    },
                ]
            )

            # Loop through and delete each subnet in the default VPC for the given region
            for subnet in describeSubnets['Subnets']:
                deleteSubnets = laEc2Region.delete_subnet(
                    SubnetId=subnet['SubnetId']
                )

            # Describe the internet gateway for the default VPC in the given region
            describeInternetGateway = laEc2Region.describe_internet_gateways(
                Filters=[
                    {
                        'Name': 'attachment.vpc-id',
                        'Values': [describeVpcs['Vpcs'][0]['VpcId']]
                    },
                ]
            )

            # Detach the internet gateway for the default VPC in the given region
            detachInternetGateway = laEc2Region.detach_internet_gateway(
                InternetGatewayId=describeInternetGateway['InternetGateways'][0]['InternetGatewayId'],
                VpcId=describeVpcs['Vpcs'][0]['VpcId']
            )

            # Delete the internet gateway for the default VPC in the given region
            deleteInternetGateway = laEc2Region.delete_internet_gateway(
                InternetGatewayId=describeInternetGateway['InternetGateways'][0]['InternetGatewayId']
            )

            # Delete the default VPC in the given region
            deleteVpc = laEc2Region.delete_vpc(
                VpcId=describeVpcs['Vpcs'][0]['VpcId']
            )
    except Exception as e:
        print(e)
        print("No Default VPCs to delete")
    return "No Default VPCs to delete"


def check_for_core(region, la_aws_access_key_id, la_aws_secret_access_key, la_aws_session_token):
    # Check to see if CFN core already exists in Linked Account

    # Initialize Cloudformation client with Linked Account credentials
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_aws_access_key_id,
        aws_secret_access_key=la_aws_secret_access_key,
        aws_session_token=la_aws_session_token,
    )

    # Check if an existing core template exists, if yes return True, otherwise False
    describeStack = laCfn.describe_stacks()
    return True if "core" in describeStack['Stacks'] else False


def delete_nipap_daemon_stack(stack_name):
    delete_stack = cloudformation.delete_stack(
        StackName=stack_name
    )
    return "nipap daemon deleted"
