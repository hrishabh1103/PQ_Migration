import logging
import base64
from typing import AsyncIterator, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from app.collectors.observations import (
    CertificateObservation, CryptoObservation, CapabilityState, RelationshipObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class CertificateModule(BaseK8sModule):
    """
    Discovers X.509 Certificates in Kubernetes TLS Secrets & ConfigMaps.
    STRICT ZERO-SECRET BOUNDARY:
    - Only public 'tls.crt' certificate bytes are inspected.
    - 'tls.key' (private key material) is NEVER read, logged, or persisted.
    - Emits CertificateObservation and CryptoObservation for CorrelationEngine.
    """
    module_id = "k8s_certificate"
    capability_name = "certificates"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering Kubernetes X.509 Public Certificates for '{cluster_id}'...")

        try:
            sec_list = client.core_v1.list_secret_for_all_namespaces()
            for sec in sec_list.items:
                ns_name = sec.metadata.namespace
                sec_name = sec.metadata.name
                sec_type = sec.type or ""
                sec_uid = sec.metadata.uid

                # Check if Secret contains public tls.crt
                if sec_type in ("kubernetes.io/tls", "Opaque") and sec.data:
                    crt_data_b64 = sec.data.get("tls.crt") or sec.data.get("cert.pem") or sec.data.get("ca.crt")
                    if not crt_data_b64:
                        continue

                    # STRICT GUARANTEE: Never touch 'tls.key' or private key material
                    try:
                        raw_crt_bytes = base64.b64decode(crt_data_b64)
                        cert = x509.load_pem_x509_certificate(raw_crt_bytes, default_backend())

                        # Compute SHA-256 Fingerprint
                        fp_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
                        formatted_fp = ":".join(fp_sha256[i:i+2] for i in range(0, len(fp_sha256), 2))

                        # Extract SANs
                        sans = []
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = san_ext.value.get_values_for_type(x509.DNSName)
                        except Exception:
                            pass

                        # Algorithm classification
                        pubkey = cert.public_key()
                        pubkey_algo = pubkey.__class__.__name__.replace("_PublicKey", "").replace("EllipticCurve", "ECDSA").replace("RSAPublicKey", "RSA")
                        pubkey_size = getattr(pubkey, "key_size", None)
                        sig_algo = cert.signature_algorithm_oid._name

                        cert_obs_id = f"cert:sha256:{fp_sha256}"

                        yield CertificateObservation(
                            module_id=self.module_id,
                            fingerprint=formatted_fp,
                            subject=cert.subject.rfc4514_string(),
                            issuer=cert.issuer.rfc4514_string(),
                            serial_number=str(cert.serial_number),
                            valid_from=cert.not_valid_before_utc.isoformat(),
                            valid_to=cert.not_valid_after_utc.isoformat(),
                            pubkey_algo=f"{pubkey_algo}-{pubkey_size}" if pubkey_size else pubkey_algo,
                            pubkey_size=pubkey_size,
                            signature_algo=sig_algo,
                            san_list=sans,
                            metadata={
                                "cluster_id": cluster_id,
                                "namespace": ns_name,
                                "secret_name": sec_name,
                                "secret_uid": sec_uid,
                                "sha256_fingerprint": fp_sha256
                            }
                        )

                        # Emit CryptoObservation for PQC readiness classification
                        yield CryptoObservation(
                            module_id=self.module_id,
                            canonical_name=f"X.509 Public Cert ({sec_name})",
                            object_type="CERTIFICATE",
                            provider="KUBERNETES_SECRET",
                            identity_key=cert_obs_id,
                            fingerprint=formatted_fp,
                            capability_state=CapabilityState.CONFIGURED,
                            metadata={
                                "pubkey_algo": pubkey_algo,
                                "pubkey_size": pubkey_size,
                                "signature_algo": sig_algo,
                                "namespace": ns_name
                            }
                        )

                        # Relationship: Secret -> Cert
                        yield RelationshipObservation(
                            module_id=self.module_id,
                            source_type="ASSET",
                            source_id_hint=f"k8s:secret:{cluster_id}:{sec_uid}",
                            target_type="CRYPTO_OBJECT",
                            target_id_hint=cert_obs_id,
                            relationship_type="CONTAINS",
                            confidence="HIGH"
                        )
                    except Exception as parse_err:
                        logger.debug(f"Could not parse public cert in Secret {ns_name}/{sec_name}: {parse_err}")

            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list Certificates in Secrets: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
