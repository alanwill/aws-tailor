# Using the /requeststatus endpoint

The /requeststatus endpoint is a GET enabled resource which allows querying Tailor for the status of requests and child tasks.

## Authorization

Like all Tailor APIs, this endpoint is authorized via AWS IAM credentials and all requests must be signed with [AWS's Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) signing process.

In order to use this endpoint IAM access and secret keys would need to be provisioned for you ahead of time. Contact the internal AWS Support Team for access.

## API Request

The request is a GET method comprised of a query parameter called `requestId`.

Sample call:

```
GET https://<tailor-api-domain>/requeststatus?requestId=bcc394a5-87c1-49bd-beac-g4308a67d227
```

## API Response

A successful response will return a 200 HTTP status code and payload similar to the following:

```
{
  "status": "complete",
  "taskStatus": {
    "vpcFlowLogs": "complete"
  },
  "accountId": "123456789012",
  "accountName": "ACME STG"
}
```

Other possible responses are:

* 400 - Typically if the `requestId` is missing or incorrectly spelled
* 404 - Typically if the requestId provided is incorrect or no longer exists in Tailor.
