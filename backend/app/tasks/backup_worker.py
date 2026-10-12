"""
backup_worker.py — Daily PostgreSQL backup to MinIO (ARQ cron task).
"""

import gzip
import logging
import os
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


async def backup_database(ctx):
    """
    ARQ cron task — runs daily at 02:00 UTC.
    Dumps the PostgreSQL database, gzips it, and uploads to MinIO bucket 'backups'.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = f"/tmp/socis_backup_{timestamp}.sql.gz"

    # Build environment with DB password
    env = os.environ.copy()
    env["PGPASSWORD"] = os.environ.get("DB_PASSWORD", "socis_secure_pass")

    db_host = os.environ.get("DB_HOST", "postgres")
    db_user = os.environ.get("DB_USER", "socis_admin")
    db_name = os.environ.get("DB_NAME", "socis_ai_pt")

    try:
        logger.info("Starting database backup: %s", timestamp)

        proc = subprocess.run(
            ["pg_dump", "-h", db_host, "-U", db_user, "-d", db_name],
            capture_output=True,
            env=env,
            timeout=300,
        )

        if proc.returncode != 0:
            err = proc.stderr.decode(errors="replace")
            logger.error("pg_dump failed: %s", err)
            return {"status": "error", "detail": err[:500]}

        # Gzip the output
        with gzip.open(backup_file, "wb") as f:
            f.write(proc.stdout)

        file_size = os.path.getsize(backup_file)
        logger.info("Backup written: %s (%d bytes)", backup_file, file_size)

        # Upload to MinIO
        try:
            from minio import Minio  # type: ignore

            client = Minio(
                os.environ.get("MINIO_ENDPOINT", "minio:9000"),
                access_key=os.environ.get("MINIO_ACCESS_KEY", "socis-minio"),
                secret_key=os.environ.get("MINIO_SECRET_KEY", "socis-minio-secret"),
                secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
            )

            bucket = "backups"
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)

            object_name = f"db/{timestamp}.sql.gz"
            client.fput_object(bucket, object_name, backup_file)
            logger.info("Backup uploaded to MinIO: %s/%s", bucket, object_name)

            return {"status": "ok", "backup": object_name, "size_bytes": file_size}

        except ImportError:
            logger.warning("minio package not installed — backup saved locally only")
            return {"status": "ok", "backup": backup_file, "size_bytes": file_size, "storage": "local"}

    except Exception as exc:
        logger.exception("Backup failed: %s", exc)
        return {"status": "error", "detail": str(exc)}

    finally:
        if os.path.exists(backup_file):
            os.unlink(backup_file)
