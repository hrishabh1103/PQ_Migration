import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, CryptoObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class ELBv2Module(BaseAWSModule):
    """
    Discovers Application & Network Load Balancers, TLS listeners, SSL policy names, and ACM certificate references.
    """
    module_name = "ELBv2"
    capability = "CLOUD_LOAD_BALANCER"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        elbv2 = sdk_client.get_client("elbv2", region_override=region)
        paginator = elbv2.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn")
                lb_name = lb.get("LoadBalancerName", "unknown-lb")
                if not lb_arn:
                    continue

                lb_asset = AssetObservation(
                    module_id="aws_elbv2",
                    provider_resource_id=lb_arn,
                    external_id=lb_name,
                    asset_type="cloud_load_balancer",
                    asset_category="infrastructure",
                    hostname=lb.get("DNSName") or lb_name,
                    metadata={
                        "load_balancer_name": lb_name,
                        "dns_name": lb.get("DNSName"),
                        "scheme": lb.get("Scheme"),
                        "vpc_id": lb.get("VpcId"),
                        "region": region,
                        "account_id": account_id
                    }
                )
                yield lb_asset

                try:
                    l_res = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
                    listeners = l_res.get("Listeners", [])
                except Exception as e:
                    logger.warning(f"ELBv2 DescribeListeners failed for '{lb_name}': {e}")
                    listeners = []

                for l in listeners:
                    l_arn = l.get("ListenerArn")
                    protocol = l.get("Protocol", "HTTP")
                    port = l.get("Port", 80)
                    ssl_policy = l.get("SslPolicy")

                    if not l_arn:
                        continue

                    listener_asset = AssetObservation(
                        module_id="aws_elbv2",
                        provider_resource_id=l_arn,
                        external_id=f"{lb_name}-{port}",
                        asset_type="cloud_listener",
                        asset_category="service",
                        hostname=f"{lb_name}:{port}",
                        metadata={
                            "protocol": protocol,
                            "port": port,
                            "ssl_policy": ssl_policy,
                            "load_balancer_arn": lb_arn,
                            "region": region
                        }
                    )
                    yield listener_asset

                    # Relationship: LOAD_BALANCER -> CONTAINS -> LISTENER
                    yield RelationshipObservation(
                        module_id="aws_elbv2",
                        source_type="ASSET",
                        source_id_hint=lb_arn,
                        target_type="ASSET",
                        target_id_hint=l_arn,
                        relationship_type="CONTAINS",
                        confidence="HIGH"
                    )

                    if ssl_policy:
                        tls_obs = CryptoObservation(
                            module_id="aws_elbv2",
                            canonical_name=ssl_policy,
                            object_type="PROTOCOL",
                            provider="AWS_ELBv2",
                            identity_key=f"crypto:{ssl_policy}",
                            metadata={"ssl_policy": ssl_policy, "port": port}
                        )
                        yield tls_obs

                        yield RelationshipObservation(
                            module_id="aws_elbv2",
                            source_type="ASSET",
                            source_id_hint=l_arn,
                            target_type="CRYPTO_OBJECT",
                            target_id_hint=f"crypto:{ssl_policy}",
                            relationship_type="USES",
                            confidence="HIGH"
                        )

                    for cert_ref in l.get("Certificates", []):
                        cert_arn = cert_ref.get("CertificateArn")
                        if cert_arn:
                            yield RelationshipObservation(
                                module_id="aws_elbv2",
                                source_type="ASSET",
                                source_id_hint=l_arn,
                                target_type="CRYPTO_OBJECT",
                                target_id_hint=cert_arn,
                                relationship_type="USES",
                                confidence="HIGH"
                            )
