# VULNERABLE: AwsHardcodedAccessKey — AWS access key ID hardcoded as a string literal
# Rule: AwsHardcodedAccessKeyTemplate | CWE-798 | Severity: CRITICAL

import boto3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_s3_client():
    """Create an S3 client using hardcoded credentials."""
    # <-- VULNERABLE: AWS credentials committed to source control
    # Bots scan GitHub/GitLab for AKIA* patterns within seconds of a push
    # Exposed keys can be used to exfiltrate data, spin up EC2 instances, or incur massive bills
    return boto3.client(
        's3',
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region_name='us-east-1',
    )


@app.route('/api/files', methods=['GET'])
def list_files():
    """List files in the application S3 bucket."""
    s3 = get_s3_client()
    response = s3.list_objects_v2(Bucket='my-app-bucket')
    files = [obj['Key'] for obj in response.get('Contents', [])]
    return jsonify({'files': files})


if __name__ == '__main__':
    app.run()
