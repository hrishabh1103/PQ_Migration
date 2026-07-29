from abc import ABC, abstractmethod
from typing import AsyncIterator
from app.collectors.observations import DiscoveryObservation
from app.connectors.azure_client import AzureSdkClient

class BaseAzureModule(ABC):
    """
    Abstract base class for modular Azure service discovery components.
    Provides failure isolation per service/resource-group and yields structured DiscoveryObservations.
    """
    module_name: str
    capability: str

    @abstractmethod
    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        pass
