"""
SOCIS-AI-PT — MinIO Object Storage Service
Handles uploading and downloading report files from S3/MinIO.
"""

import io
import urllib3
from pathlib import Path
from typing import Optional, BinaryIO

from minio import Minio
from minio.error import S3Error
import logging

from app.config import settings

log = logging.getLogger(__name__)

class StorageService:
    def __init__(self):
        self.enabled = bool(settings.MINIO_ENDPOINT)
        self.client = None
        self.bucket = settings.MINIO_BUCKET

        if self.enabled:
            # Disable urllib3 warnings for self-signed certs if secure is false
            if not settings.MINIO_SECURE:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
            try:
                self.client = Minio(
                    settings.MINIO_ENDPOINT,
                    access_key=settings.MINIO_ACCESS_KEY,
                    secret_key=settings.MINIO_SECRET_KEY,
                    secure=settings.MINIO_SECURE,
                )
                self._ensure_bucket()
            except Exception as e:
                log.error(f"Failed to initialize MinIO client: {e}")
                self.enabled = False

    def _ensure_bucket(self):
        """Ensure the target bucket exists, creating it if necessary."""
        if not self.client:
            return
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
                log.info(f"Created MinIO bucket: {self.bucket}")
            self._ensure_lifecycle()
        except S3Error as e:
            log.error(f"MinIO bucket error: {e}")
            self.enabled = False

    def _ensure_lifecycle(self):
        """Apply a retention lifecycle rule so old reports auto-expire.

        Controlled by REPORT_RETENTION_DAYS (0 disables). Best-effort: a failure
        here (older MinIO, missing permission) must not break storage, so it is
        logged and swallowed.
        """
        retention = int(getattr(settings, "REPORT_RETENTION_DAYS", 0) or 0)
        if retention <= 0 or not self.client:
            return
        try:
            from minio.lifecycleconfig import LifecycleConfig, Rule, Expiration, Filter
            config = LifecycleConfig(
                [
                    Rule(
                        rule_id="expire-old-reports",
                        status="Enabled",
                        rule_filter=Filter(prefix=""),
                        expiration=Expiration(days=retention),
                    ),
                ]
            )
            self.client.set_bucket_lifecycle(self.bucket, config)
            log.info(f"MinIO lifecycle: reports expire after {retention} days")
        except Exception as e:  # noqa: BLE001 - best-effort, never fatal
            log.warning(f"Could not set MinIO lifecycle policy (non-fatal): {e}")

    def upload_file(self, object_name: str, file_path: Optional[Path] = None, content: Optional[bytes] = None) -> bool:
        """Upload a file or raw bytes to MinIO."""
        if not self.enabled or not self.client:
            return False

        try:
            if file_path:
                self.client.fput_object(self.bucket, object_name, str(file_path))
                return True
            elif content is not None:
                data_stream = io.BytesIO(content)
                self.client.put_object(
                    self.bucket,
                    object_name,
                    data_stream,
                    length=len(content),
                )
                return True
            else:
                raise ValueError("Must provide either file_path or content")
        except Exception as e:
            log.error(f"MinIO upload failed for {object_name}: {e}")
            return False

    def download_file(self, object_name: str, file_path: Path) -> bool:
        """Download file from MinIO to local filesystem."""
        if not self.enabled or not self.client:
            return False

        try:
            self.client.fget_object(self.bucket, object_name, str(file_path))
            return True
        except Exception as e:
            log.error(f"MinIO download failed for {object_name}: {e}")
            return False

    def get_object_data(self, object_name: str) -> Optional[bytes]:
        """Fetch raw bytes for an object directly from MinIO."""
        if not self.enabled or not self.client:
            return None

        try:
            response = self.client.get_object(self.bucket, object_name)
            data = response.read()
            response.close()
            response.release_conn()
            return data
        except Exception as e:
            log.error(f"MinIO get_object_data failed for {object_name}: {e}")
            return None


storage_service = StorageService()
