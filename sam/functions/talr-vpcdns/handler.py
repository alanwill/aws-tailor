# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import os
import sys
import time
from datetime import datetime

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory


# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
dynamodb = boto3.resource('dynamodb')
sts = boto3.client('sts')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    accountInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_ACCOUNTINFO'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    incomingMessage = event['Records'][0]['Sns']['Message'].split('\n')
    accountLaId = None
    stackId = None
    region = None
    laVpcId = None

    # Parse the SNS message with the Cloudformation response. Since it's not in JSON format, it needs to be converted
    # to a dictionary first
    cfnIncomingMessage = {}
    for line in incomingMessage:
        key = line.partition("=")[0]
        value = line.partition("=")[2].lstrip("'").rstrip("'")
        cfnIncomingMessage[key] = value
    print("cfnIncomingMessage:", cfnIncomingMessage)

    # Check each incoming event and determine whether the Stack has completed successfully, only proceed if yes
    # otherwise exit.
    try:
        if "arn:aws:cloudformation:" in cfnIncomingMessage['StackId'] and \
                        cfnIncomingMessage['ResourceStatus'] == "CREATE_COMPLETE" and \
                        cfnIncomingMessage['StackName'] == "core":
            stackId = cfnIncomingMessage['StackId']
            region = stackId.split(":")[3]
            physicalResourceId = cfnIncomingMessage['PhysicalResourceId']
            accountLaId = cfnIncomingMessage['Namespace']
            print("StackId:", stackId)
            print("region:", region)
            print("PhysicalResourceId:", physicalResourceId)
            print("accountLaId:", accountLaId)
    except KeyError as e:
        print(e)

        # Check if the payload is from talr-accountupdate-vpcdns
        try:
            if "accountId" in cfnIncomingMessage:
                accountLaId = cfnIncomingMessage['accountId']
                region = cfnIncomingMessage['region']
                laVpcId = cfnIncomingMessage['vpcId']
                requestId = cfnIncomingMessage['requestId']
        except KeyError as e:
            print(e)
            return "Nothing to do"

    # Look up the account info from the known accountId
    getAccountId = accountInfo.query(
        IndexName='gsiAccountId',
        KeyConditionExpression=Key('accountId').eq(accountLaId)
    )
    try:
        if requestId:
            pass
    except Exception as e:
        print(e)
        requestId = getAccountId['Items'][0]['requestId']
    accountCbAlias = getAccountId['Items'][0]['accountCbAlias']

    # Update task start status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "VPCDNS",
            "function": "talr-vpcdns",
            "message": stackId
        }
    )

    # Lookup cbInfo variables
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']
    accountCsId = getCbInfo['Item']['accountCsId']
    accountRouteTableRouteThreshold = getCbInfo['Item']['accountRouteTableRouteThreshold']


    laCredentials = initialize_la_services(account_cb_id=accountCbId, la_account_id=accountLaId)
    csCredentials = initialize_la_services(account_cb_id=accountCbId, la_account_id=accountCsId)

    dnsStack = get_dns_server_ips(cs_credentials=csCredentials,
                                  routes_threshold=accountRouteTableRouteThreshold,
                                  region=region)
    if isinstance(dnsStack, dict):
        csVpcId = dnsStack['vpcId']
        if laVpcId is None:
            laVpcId = get_la_vpc_id(laCredentials, region)
        vpcPeeringId = create_vpc_peer(la_credentials=laCredentials,
                                    cs_credentials=csCredentials,
                                    account_cs_id=accountCsId,
                                    account_la_id=accountLaId,
                                    cs_vpc_id=csVpcId,
                                    la_vpc_id=laVpcId,
                                    region=region)
    else:
        return dnsStack
    add_routes(cs_credentials=csCredentials,
               la_credentials=laCredentials,
               peering_id=vpcPeeringId,
               la_vpc_id=laVpcId,
               cs_vpc_id=csVpcId,
               region=region)
    add_dhcp_optionset(la_credentials=laCredentials,
                       la_vpc_id=laVpcId,
                       dns_server_1=dnsStack['dnsA'],
                       dns_server_2=dnsStack['dnsB'],
                       region=region)

    # Update task end status
    taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "VPCDNS",
            "function": "talr-vpcdns",
            "message": "-"
        }
    )

    return

def add_routes(cs_credentials, la_credentials, peering_id, cs_vpc_id, la_vpc_id, region):

    # Get Core Services VPC cidr
    csEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=cs_credentials[0],
        aws_secret_access_key=cs_credentials[1],
        aws_session_token=cs_credentials[2],
    )

    csVpcId = csEc2.describe_vpcs(
        VpcIds=[cs_vpc_id],
    )
    csVpcCidr = csVpcId['Vpcs'][0]['CidrBlock']

    csRouteTables = csEc2.describe_route_tables(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [cs_vpc_id]
            },
        ],
    )
    csRouteTableIds = list()
    for i in csRouteTables['RouteTables']:
        if i['Associations'][0]['Main'] is False:
            csRouteTableIds.append(i['RouteTableId'])
        else:
            continue

    # Get linked account VPC cidr
    laEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    laVpcId = laEc2.describe_vpcs(
        VpcIds=[la_vpc_id],
    )
    laVpcCidr = laVpcId['Vpcs'][0]['CidrBlock']

    laRouteTables = laEc2.describe_route_tables(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [la_vpc_id]
            },
        ],
    )
    laRouteTableIds = list()
    for i in laRouteTables['RouteTables']:
        if i['Associations'][0]['Main'] is False:
            laRouteTableIds.append(i['RouteTableId'])
        else:
            continue


    # Add VPC peering routes
    try:
        for i in csRouteTableIds:
            csEc2.create_route(
                DestinationCidrBlock=laVpcCidr,
                RouteTableId=i,
                VpcPeeringConnectionId=peering_id
            )

        for i in laRouteTableIds:
            laEc2.create_route(
                DestinationCidrBlock=csVpcCidr,
                RouteTableId=i,
                VpcPeeringConnectionId=peering_id
            )
    except ClientError as e:
        if e.response['Error']['Code'] == 'RouteAlreadyExists':
            raise Exception({"code": "4090", "message": "ERROR: Conflict"})
        else:
            return e

    return

def add_dhcp_optionset(la_credentials, la_vpc_id, dns_server_1, dns_server_2, region):

    # Initiate linked account ec2 client
    laEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    if region == 'us-east-1':
        domainName = 'ec2.internal'
    else:
        domainName = region + '.compute.internal'
    dhcpOptionsset = laEc2.create_dhcp_options(
        DhcpConfigurations=[
            {
                'Key': 'domain-name-servers',
                'Values': [dns_server_1, dns_server_2, 'AmazonProvidedDNS']
            },
            {
                'Key': 'domain-name',
                'Values': [domainName]
            },
        ],
    )

    laEc2.associate_dhcp_options(
        DhcpOptionsId=dhcpOptionsset['DhcpOptions']['DhcpOptionsId'],
        VpcId=la_vpc_id,
    )

    return

def check_vpc_eligible(cs_credentials, vpc_id, routes_threshold, region):

    # Initiate coreservices ec2 client
    csEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=cs_credentials[0],
        aws_secret_access_key=cs_credentials[1],
        aws_session_token=cs_credentials[2],
    )

    routeTables = csEc2.describe_route_tables(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [vpc_id]
            },
        ],
    )

    largeRouteTables = []
    for i in routeTables['RouteTables']:
        if len(i['Routes']) >= routes_threshold:
            largeRouteTables.append({'routeTableId': i['RouteTableId'], 'routeCount': len(i['Routes'])})
        else:
            continue
    if len(largeRouteTables) >= 1:
        return False
    else:
        return True

def get_la_vpc_id(la_credentials, region):

    # Lookup vpcid
    laCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )
    # Look up CFN stack Outputs
    getStack = laCfn.describe_stacks(
        StackName='core'
    )

    # Extract vpc id
    laVpcId = None
    cfnOutput = getStack['Stacks'][0]['Outputs']
    for i in cfnOutput:
        if i['OutputKey'] == "VPC":
            laVpcId = i['OutputValue']
        else:
            continue

    return laVpcId

def get_dns_server_ips(cs_credentials, routes_threshold, region):

    # Lookup vpcid
    csCfn = boto3.client(
        'cloudformation',
        region_name=region,
        aws_access_key_id=cs_credentials[0],
        aws_secret_access_key=cs_credentials[1],
        aws_session_token=cs_credentials[2],
    )
    # Look up CFN stack Outputs
    getStack = csCfn.describe_stacks()

    vpcId = None
    dnsA = None
    dnsB = None
    dnsStacks = []
    for i in getStack['Stacks']:
        if i['StackName'].startswith('vpc-dns-'):
            for ii in i['Outputs']:
                if ii['OutputKey'] == 'VPCId':
                    vpcId = ii['OutputValue']
                elif ii['OutputKey'] == 'DNSA':
                    dnsA = ii['OutputValue']
                elif ii['OutputKey'] == 'DNSB':
                    dnsB = ii['OutputValue']
            dnsStacks.append({'stackId': i['StackId'], 'vpcId': vpcId, 'dnsA': dnsA, 'dnsB': dnsB})
        else:
            continue

    noVpcs = 0
    for i in dnsStacks:
        eligible = check_vpc_eligible(cs_credentials=cs_credentials,
                        vpc_id=i['vpcId'],
                        routes_threshold=routes_threshold,
                        region=region)
        if eligible is True:
            return i
        else:
            noVpcs += 1
            continue

    if noVpcs >= 1:
        return "No VPCs in CoreServices available to fulfill this peering request"

def create_vpc_peer(la_credentials, cs_credentials, account_cs_id, account_la_id, cs_vpc_id, la_vpc_id, region):

    # Initiate coreservices ec2 client
    csEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=cs_credentials[0],
        aws_secret_access_key=cs_credentials[1],
        aws_session_token=cs_credentials[2],
    )

    initiatePeeringRequest = csEc2.create_vpc_peering_connection(
        PeerOwnerId=account_la_id,
        PeerVpcId=la_vpc_id,
        VpcId=cs_vpc_id
    )
    vpcPeeringConnectionId = initiatePeeringRequest['VpcPeeringConnection']['VpcPeeringConnectionId']

    csWaiter = csEc2.get_waiter('vpc_peering_connection_exists')
    csWaiter.wait(
        Filters=[
            {
                'Name': 'status-code',
                'Values': ['pending-acceptance']
            },
        ],
        VpcPeeringConnectionIds=[vpcPeeringConnectionId]
    )

    # Tag the VPC peer with the account Id of the linked account
    csEc2.create_tags(
        Resources=[vpcPeeringConnectionId],
        Tags=[
            {
                'Key': 'Name',
                'Value': account_la_id
            },
        ]
    )

    # Initiate linked account ec2 client
    laEc2 = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=la_credentials[0],
        aws_secret_access_key=la_credentials[1],
        aws_session_token=la_credentials[2],
    )

    laEc2.accept_vpc_peering_connection(
        VpcPeeringConnectionId=vpcPeeringConnectionId
    )

    laWaiter = csEc2.get_waiter('vpc_peering_connection_exists')
    laWaiter.wait(
        Filters=[
            {
                'Name': 'status-code',
                'Values': ['active']
            },
        ],
        VpcPeeringConnectionIds=[vpcPeeringConnectionId]
    )

    # Tag the VPC peer with the account Id of the Core Services account
    laEc2.create_tags(
        Resources=[vpcPeeringConnectionId],
        Tags=[
            {
                'Key': 'Name',
                'Value': account_cs_id
            },
        ]
    )

    return vpcPeeringConnectionId

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

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")
