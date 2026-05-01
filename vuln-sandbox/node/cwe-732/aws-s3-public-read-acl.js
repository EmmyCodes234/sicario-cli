// VULNERABLE: aws-s3-public-read-acl — S3 object uploaded with public-read ACL
// Rule: AwsS3PublicReadAcl | CWE-732 | Severity: HIGH

const AWS = require('aws-sdk');
const fs = require('fs');

const s3 = new AWS.S3({ region: 'us-east-1' });

function uploadFile(filePath, bucketName, key) {
  const fileContent = fs.readFileSync(filePath);

  // VULNERABLE: ACL:'public-read' makes the object publicly accessible to anyone
  const params = {
    Bucket: bucketName,
    Key: key,
    Body: fileContent,
    ACL: 'public-read',
  };

  return s3.upload(params).promise();
}

uploadFile('./report.pdf', 'my-bucket', 'reports/report.pdf');
