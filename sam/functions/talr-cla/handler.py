# coding: utf-8
from __future__ import (absolute_import, division, print_function, unicode_literals)

import json
import logging
import boto3
import os
import sys
import time
import datetime
import hashlib
import hmac

# Path to modules needed to package local lambda function for upload
currentdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(currentdir, "./vendored"))

# Modules downloaded into the vendored directory
import requests

# Logging for Serverless
log = logging.getLogger()
log.setLevel(logging.DEBUG)

# Initializing AWS services
sns = boto3.client('sns')
sts = boto3.client('sts')
dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    log.debug("Received event {}".format(json.dumps(event)))

    taskStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_TASKSTATUS'])
    cbInfo = dynamodb.Table(os.environ['TAILOR_TABLENAME_CBINFO'])
    claStatus = dynamodb.Table(os.environ['TAILOR_TABLENAME_CLASTATUS'])
    incomingMessage = json.loads(event['Records'][0]['Sns']['Message'])
    requestId = incomingMessage['lambda']['requestId']
    accountTagLongProjectName = incomingMessage['lambda']['accountTagLongProjectName']
    accountCbAlias = incomingMessage['lambda']['accountCbAlias']
    accountEmailAddress = incomingMessage['lambda']['accountEmailAddress']

    # Update task start status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "start",
            "taskName": "CLA_SUBMISSION",
            "function": "talr-cla",
            "message": "-"
        }
    )

    # Querying cbInfo to extract other cb related values like accountNumber
    getCbInfo = cbInfo.get_item(
        Key={
            'accountCbAlias': accountCbAlias
        }
    )
    accountCbId = getCbInfo['Item']['accountCbId']

    # Assuming Payer/CB role and extracting credentials to be used by the CLA call
    payerAssumeRole = sts.assume_role(
        RoleArn="arn:aws:iam::" + accountCbId + ":role/tailor",
        RoleSessionName="talrClaPayerAssumeRole"
    )
    payerCredentials = payerAssumeRole['Credentials']
    aws_access_key_id = payerCredentials['AccessKeyId']
    aws_secret_access_key = payerCredentials['SecretAccessKey']
    aws_session_token = payerCredentials['SessionToken']

    accountRequest = {
                       "AccountName": accountTagLongProjectName,
                       "Email": accountEmailAddress,
                       "IamUserAccessToBilling": "ALLOW",
                       "RoleName": "PayerAccountAccessRole"
                    }

    endpoint, headers, data = sig_v4_post(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          aws_session_token=aws_session_token,
                                          payload=accountRequest)
    createAccountsResponse = requests.post(endpoint, headers=headers, data=data)
    responseData = json.loads(createAccountsResponse.content)
    print(responseData)

    updateClaStatus = claStatus.put_item(
        Item={
            "requestId": requestId,
            "claRequestId": responseData['CreateAccountStatus']['Id'],
            "accountName": responseData['CreateAccountStatus']['AccountName'],
            "requestedTimestamp": str(responseData['CreateAccountStatus']['RequestedTimestamp']),
            "state": responseData['CreateAccountStatus']['State']
        }
    )

    # Update task end status
    updateStatus = taskStatus.put_item(
        Item={
            "requestId": requestId,
            "eventTimestamp": str(time.time()),
            "period": "end",
            "taskName": "CLA_SUBMISSION",
            "function": "talr-cla",
            "message": "-"
        }
    )


    # -------------------------------------------------------------------------------------------------
    # This version makes a POST request and passes request parameters
    # in the body (payload) of the request. Auth information is passed in
    # an Authorization header.
def sig_v4_post(payload, aws_access_key_id, aws_secret_access_key, aws_session_token):
    if aws_access_key_id is None or aws_secret_access_key is None or aws_session_token is None:
        print('No credentials available.')
        sys.exit()

    data = json.dumps(payload)

    method = 'POST'
    service = 'organizations'
    host = 'organizations.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://organizations.us-east-1.amazonaws.com'
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'AWSOrganizationsV20161128.CreateAccount'

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    canonical_uri = '/'

    # # Step 3: Create the canonical query string. In this example, request
    # parameters are passed in the body of the request and the query string
    # is blank.
    canonical_querystring = ''

    # Step 4: Create the canonical headers. Header names and values
    # must be trimmed and lowercase, and sorted in ASCII order.
    # Note that there is a trailing \n.
    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n'

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers include those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    # For DynamoDB, content-type and x-amz-target are also required.
    signed_headers = 'content-type;host;x-amz-date;x-amz-target'

    # Step 6: Create payload hash. In this example, the payload (body of
    # the request) contains the request parameters.
    payload_hash = hashlib.sha256(data).hexdigest()

    # Step 7: Combine elements to create create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined below.
    signing_key = getSignatureKey(aws_secret_access_key, date_stamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # Put the signature information in a header named Authorization.
    authorization_header = algorithm + ' ' + 'Credential=' + aws_access_key_id + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    # For CreateLinkedAccount, the request can include any headers, but MUST include "host", "x-amz-date",
    # "x-amz-target", "content-type", and "Authorization". Except for the authorization
    # header, the headers must be included in the canonical_headers and signed_headers values, as
    # noted earlier. Order here is not significant.
    # # Python note: The 'host' header is added automatically by the Python 'requests' library.
    headers = {'Content-Type': content_type,
               'X-Amz-Date': amz_date,
               'X-Amz-Target': amz_target,
               'X-Amz-security-token': aws_session_token,
               'Authorization': authorization_header}

    return endpoint, headers, data


# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning