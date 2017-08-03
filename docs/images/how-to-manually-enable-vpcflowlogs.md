# How to manually enable VPC Flow Logs

## Prerequisites

* IAM keys with full access to VPC and Cloudwatch Logs
* AWS CLI already installed and configured

## Step 1

### Set required environment variables
```
export vpcRegion="us-east-1"
export vpcId="vpc-3c779159"
```

### Create Cloudwatch Logs Group

Note: Replace `myprofilename` with the name of the profile you created as part of the AWS CLI configuration

```
aws logs create-log-group --log-group-name /`aws iam list-account-aliases --profile myprofilename --output text --query 'AccountAliases[0]'`/vpcflowlogs/`echo $vpcRegion`/`echo $vpcId` --region $vpcRegion --profile myprofilename
```

## Step 2

### Set Log Group Retention

First lookup the full log group name:
```
aws logs describe-log-groups --profile myprofilename --region $vpcRegion
```

Replace `my-logs` with the log group name, then run the command below to set the retention:
```
aws logs put-retention-policy --log-group-name my-logs --retention-in-days 7 --region `echo $vpcRegion` --profile myprofilename
```

## Step 3

### Create Flow Logs
