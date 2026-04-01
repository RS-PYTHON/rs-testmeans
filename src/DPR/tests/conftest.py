import os


def export_aws_credentials():
    """Export AWS credentials as environment variables for DPR moto tests."""
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            "S3_ACCESSKEY": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "S3_SECRETKEY": "testing",
            "AWS_SECURITY_TOKEN": "testing",
            "S3_ENDPOINT": "http://localhost:5555",
            "AWS_SESSION_TOKEN": "testing",
            "S3_REGION": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
        }
    )
