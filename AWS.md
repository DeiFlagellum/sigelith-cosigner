# Running the cosigner in AWS Lambda

The same program, with the key in AWS KMS (it never leaves the hardware security module) and
the state in DynamoDB. Region in the examples: `eu-central-1` (Frankfurt). Cost: about
1 USD per month for the KMS key; Lambda, EventBridge Scheduler and DynamoDB stay within their
free tiers (43 200 runs a month). The cosigner has no public endpoint, so nobody can run up
the bill.

## 1. KMS key

Key type asymmetric, usage **Sign and verify**, spec **ECC_NIST_EDWARDS25519**. Note the key ARN.

## 2. DynamoDB table

Name `sigelith-cosigner-state`, partition key `pk` (String), capacity mode **provisioned**,
1 read and 1 write unit (free tier). The cosigner keeps a single item, `pk = "state"`.

## 3. IAM role for the function

Trusted entity: Lambda. Permissions — attach `AWSLambdaBasicExecutionRole` (CloudWatch Logs)
and this inline policy (fill in the ARNs):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "<KMS key ARN>",
      "Condition": {
        "StringEquals": {"kms:SigningAlgorithm": "ED25519_SHA_512", "kms:MessageType": "RAW"}
      }
    },
    {"Effect": "Allow", "Action": "kms:GetPublicKey", "Resource": "<KMS key ARN>"},
    {
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
      "Resource": "<DynamoDB table ARN>"
    }
  ]
}
```

This role must be **the only** principal allowed to sign with the key. Remove any other
user or role that has `kms:Sign` on it.

## 4. Function

- Runtime **Amazon Linux 2023** (`provided.al2023`), architecture **arm64**, handler `bootstrap`;
- code: `sigelith-cosigner-lambda-arm64.zip` from the release (check its SHA-256);
- memory 128 MB, timeout 30 s, **reserved concurrency 1** (never two runs at once);
- environment:

| variable | value |
|---|---|
| `COSIGNER_NAME` | e.g. `aws-eu-central-1` |
| `LOG_URL` | `https://sigelith.org` |
| `KMS_KEY_ID` | the key ARN |
| `STATE_TABLE` | `sigelith-cosigner-state` |

Test it with an empty event `{}`: the result shows `new_entries`, `size`, `signed`.

## 5. Schedule

EventBridge Scheduler: recurring, `rate(1 minute)`, flexible time window **off**, target the
function. The scheduler needs a role that may invoke the function (the console creates it).

## 6. Alarms

An anomaly ends the invocation with an error. Create a CloudWatch alarm on the function's
`Errors` metric (sum ≥ 1 in 5 minutes) with an SNS e-mail notification. Clear an alarm after
you have decided, with the test event `{"clear_alarm": true}`.
