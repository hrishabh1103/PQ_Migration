import logging
import re
from typing import Dict, Any, Optional, List
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

# Safe tag key allowlist and secret pattern matching
SAFE_TAG_KEYS = {"name", "environment", "env", "project", "owner", "service", "app", "application", "component", "role", "tier"}
SECRET_PATTERN = re.compile(r"(secret|token|password|passwd|key|credential|private|auth|bearer)", re.IGNORECASE)

class AWSSdkClient:
    """
    Shared AWS SDK Execution Layer managing standard SDK credential provider chains,
    STS identity validation, region scoping, retry policy, rate limiting, and zero-secret safety.
    """
    def __init__(
        self,
        region_name: str = "us-east-1",
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None
    ):
        self.region_name = region_name
        self.profile_name = profile_name
        self.role_arn = role_arn
        self.external_id = external_id

        # Standard retry configuration
        self.boto_config = Config(
            region_name=region_name,
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=10,
            read_timeout=30
        )

        self._session = self._create_session()

    def _create_session(self) -> boto3.Session:
        """
        Create base boto3 session using standard credential provider chain.
        """
        # Ensure trailing whitespace from .env files is stripped
        import os
        key_id = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        if key_id and os.environ.get("AWS_ACCESS_KEY_ID") != key_id.strip():
            os.environ["AWS_ACCESS_KEY_ID"] = key_id.strip()
        if secret_key and os.environ.get("AWS_SECRET_ACCESS_KEY") != secret_key.strip():
            os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key.strip()

        if self.profile_name:
            session = boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
        else:
            session = boto3.Session(region_name=self.region_name)

        if self.role_arn:
            sts = session.client("sts", config=self.boto_config)
            kwargs: Dict[str, Any] = {
                "RoleArn": self.role_arn,
                "RoleSessionName": "QDiscoveryAWSConnector"
            }
            if self.external_id:
                kwargs["ExternalId"] = self.external_id

            assumed = sts.assume_role(**kwargs)
            creds = assumed["Credentials"]

            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region_name
            )

        return session

    def get_client(self, service_name: str, region_override: Optional[str] = None) -> Any:
        """
        Get service client with proper region configuration.
        """
        region = region_override or self.region_name
        cfg = Config(
            region_name=region,
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=10,
            read_timeout=30
        )
        return self._session.client(service_name, config=cfg)

    def validate_identity(self) -> Dict[str, Any]:
        """
        Validate AWS identity using STS GetCallerIdentity.
        Returns safe account metadata (Account, Arn, UserId).
        Zero secret leakage: Credentials are never exposed.
        """
        try:
            sts = self.get_client("sts", region_override="us-east-1")
            identity = sts.get_caller_identity()
            arn = identity.get("Arn", "")
            account = identity.get("Account", "")
            user_id = identity.get("UserId", "")
            partition = arn.split(":")[1] if ":" in arn else "aws"

            logger.info(f"STS Caller Identity validated for AWS Account: {account}")
            return {
                "account_id": account,
                "arn": arn,
                "user_id": user_id,
                "partition": partition,
                "validated": True
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "AuthError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"STS Identity validation failed [{code}]: {msg}")
            return {
                "account_id": "UNKNOWN",
                "arn": "",
                "user_id": "",
                "partition": "aws",
                "validated": False,
                "error": f"[{code}] {msg}"
            }

    @staticmethod
    def sanitize_tags(tags: Any) -> Dict[str, str]:
        """
        Sanitize AWS tags according to safe metadata allowlist.
        Redacts values matching secret patterns.
        """
        sanitized: Dict[str, str] = {}
        if not tags:
            return sanitized

        tag_list: List[Dict[str, str]] = []
        if isinstance(tags, dict):
            tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
        elif isinstance(tags, list):
            tag_list = tags

        for t in tag_list:
            key = str(t.get("Key", "")).strip()
            val = str(t.get("Value", "")).strip()

            if not key:
                continue

            # Check safe key allowlist
            if key.lower() not in SAFE_TAG_KEYS:
                continue

            # Check for secret values
            if SECRET_PATTERN.search(key) or SECRET_PATTERN.search(val):
                val = "[REDACTED]"

            sanitized[key] = val

        return sanitized

    @staticmethod
    def classify_error(err: Exception) -> str:
        """
        Classify boto3/botocore ClientError into standard error status string.
        """
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                return "ACCESS_DENIED"
            elif code in ("Throttling", "ThrottlingException", "RequestLimitExceeded"):
                return "THROTTLED"
            elif code in ("NoSuchResource", "ResourceNotFoundException"):
                return "NOT_FOUND"
            return f"AWS_ERROR_{code}"
        return f"ERROR_{err.__class__.__name__}"
