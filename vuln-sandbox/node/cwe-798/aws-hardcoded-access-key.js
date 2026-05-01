// VULNERABLE: aws-hardcoded-access-key — AWS credentials hardcoded in source
// Rule: AwsHardcodedAccessKey | CWE-798 | Severity: CRITICAL

const AWS = require('aws-sdk');

// VULNERABLE: hardcoded AWS access key ID and secret — will be exposed in version control
const s3 = new AWS.S3({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
});

s3.listBuckets((err, data) => {
  if (err) console.error(err);
  else console.log(data.Buckets);
});
