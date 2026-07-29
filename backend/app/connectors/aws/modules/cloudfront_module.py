import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, CryptoObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class CloudFrontModule(BaseAWSModule):
    """
    Discovers CloudFront CDN distributions, viewer protocol policies, minimum TLS versions, and ACM cert ARNs.
    """
    module_name = "CloudFront"
    capability = "CLOUD_CDN"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        cloudfront = sdk_client.get_client("cloudfront", region_override="us-east-1")
        paginator = cloudfront.get_paginator("list_distributions")

        target_account_arn = f"arn:aws:::{account_id}"

        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {}).get("Items", [])
            for dist in dist_list:
                dist_id = dist.get("Id")
                if not dist_id:
                    continue

                arn = dist.get("ARN", f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}")
                domain_name = dist.get("DomainName", f"{dist_id}.cloudfront.net")
                enabled = dist.get("Enabled", True)

                viewer_cert = dist.get("ViewerCertificate", {})
                min_tls = viewer_cert.get("MinimumProtocolVersion", "TLSv1.2_2021")
                acm_cert_arn = viewer_cert.get("ACMCertificateArn")

                cdn_asset = AssetObservation(
                    module_id="aws_cloudfront",
                    provider_resource_id=arn,
                    external_id=dist_id,
                    asset_type="cloud_cdn",
                    asset_category="infrastructure",
                    hostname=domain_name,
                    metadata={
                        "distribution_id": dist_id,
                        "domain_name": domain_name,
                        "enabled": enabled,
                        "minimum_protocol_version": min_tls,
                        "acm_certificate_arn": acm_cert_arn,
                        "account_id": account_id
                    }
                )
                yield cdn_asset

                # Relationship: AWS_ACCOUNT -> CONTAINS -> CLOUDFRONT
                yield RelationshipObservation(
                    module_id="aws_cloudfront",
                    source_type="ASSET",
                    source_id_hint=target_account_arn,
                    target_type="ASSET",
                    target_id_hint=arn,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )

                # TLS Configuration Observation
                tls_obs = CryptoObservation(
                    module_id="aws_cloudfront",
                    canonical_name=min_tls,
                    object_type="PROTOCOL",
                    provider="AWS_CloudFront",
                    identity_key=f"crypto:{min_tls}",
                    metadata={"minimum_protocol_version": min_tls, "distribution_id": dist_id}
                )
                yield tls_obs

                yield RelationshipObservation(
                    module_id="aws_cloudfront",
                    source_type="ASSET",
                    source_id_hint=arn,
                    target_type="CRYPTO_OBJECT",
                    target_id_hint=f"crypto:{min_tls}",
                    relationship_type="USES",
                    confidence="HIGH"
                )

                if acm_cert_arn:
                    yield RelationshipObservation(
                        module_id="aws_cloudfront",
                        source_type="ASSET",
                        source_id_hint=arn,
                        target_type="CRYPTO_OBJECT",
                        target_id_hint=acm_cert_arn,
                        relationship_type="USES",
                        confidence="HIGH"
                    )
