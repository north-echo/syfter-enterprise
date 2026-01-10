"""
S3/MinIO storage backend.
"""

import boto3
from botocore.exceptions import ClientError

from .base import StorageBackend
from ..config import StorageConfig


class S3Storage(StorageBackend):
    """S3/MinIO storage backend."""

    def __init__(self, config: StorageConfig):
        """
        Initialize S3 storage.

        Args:
            config: Storage configuration
        """
        self.bucket = config.s3_bucket
        self.config = config

        # Create S3 client
        client_kwargs = {
            "aws_access_key_id": config.s3_access_key,
            "aws_secret_access_key": config.s3_secret_key,
            "region_name": config.s3_region,
        }

        # If endpoint is specified, it's MinIO or compatible
        if config.s3_endpoint:
            client_kwargs["endpoint_url"] = config.s3_endpoint
            client_kwargs["config"] = boto3.session.Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
            )

        self.client = boto3.client("s3", **client_kwargs)

        # Ensure bucket exists
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        """Create bucket if it doesn't exist."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                # Bucket doesn't exist, create it
                if self.config.s3_endpoint:
                    # MinIO doesn't need location constraint
                    self.client.create_bucket(Bucket=self.bucket)
                else:
                    # AWS S3 needs location constraint for non-us-east-1
                    if self.config.s3_region != "us-east-1":
                        self.client.create_bucket(
                            Bucket=self.bucket,
                            CreateBucketConfiguration={
                                "LocationConstraint": self.config.s3_region
                            },
                        )
                    else:
                        self.client.create_bucket(Bucket=self.bucket)
            else:
                raise

    def put(self, key: str, data: bytes) -> int:
        """Store data at the given key."""
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
        )
        return len(data)

    def get(self, key: str) -> bytes:
        """Retrieve data from the given key."""
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchKey":
                raise FileNotFoundError(f"Key not found: {key}")
            raise

    def delete(self, key: str) -> bool:
        """Delete data at the given key."""
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError:
            return False

    def get_url(self, key: str, expires_in: int = 3600) -> str:
        """Get a presigned URL for the object."""
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_in,
        )

    def get_upload_url(self, key: str, expires_in: int = 3600) -> str:
        """Get a presigned URL for uploading."""
        return self.client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_in,
        )
