# VULNERABLE: AwsS3PublicReadAcl — S3 object uploaded with ACL='public-read'
# Rule: AwsS3PublicReadAclTemplate | CWE-732 | Severity: HIGH

import boto3
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

s3 = boto3.client('s3', region_name='us-east-1')
BUCKET = os.environ.get('S3_BUCKET', 'my-app-bucket')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a file to S3 and return its public URL."""
    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'error': 'No file provided'}), 400

    key = f"uploads/{uploaded.filename}"

    # <-- VULNERABLE: ACL='public-read' makes the object readable by anyone on the internet
    # Sensitive files (PII, internal docs, backups) become publicly accessible
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=uploaded.read(),
        ContentType=uploaded.content_type,
        ACL='public-read',  # <-- VULNERABLE
    )

    url = f"https://{BUCKET}.s3.amazonaws.com/{key}"
    return jsonify({'url': url, 'key': key})


if __name__ == '__main__':
    app.run()
