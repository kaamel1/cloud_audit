"""
Cloud Auditor Factory
"""
from typing import Dict, Any, Optional
from .base import CloudAuditorFactory, CloudAuditor, CloudSession


class CloudAuditorManager:
    """Manager for cloud auditor factories"""

    def __init__(self):
        self._factories: Dict[str, CloudAuditorFactory] = {}

    def register_factory(self, provider_name: str, factory: CloudAuditorFactory) -> None:
        """Register a cloud auditor factory"""
        self._factories[provider_name] = factory

    def get_factory(self, provider_name: str) -> CloudAuditorFactory:
        """Get a cloud auditor factory by provider name"""
        if provider_name not in self._factories:
            raise ValueError(f"Provider '{provider_name}' not supported")
        return self._factories[provider_name]

    def create_session(self, provider_name: str, **kwargs) -> CloudSession:
        """Create a session for the specified cloud provider"""
        factory = self.get_factory(provider_name)
        return factory.create_session(**kwargs)

    def create_auditor(self, provider_name: str, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        """Create an auditor for the specified cloud provider"""
        factory = self.get_factory(provider_name)
        return factory.create_auditor(session, output_dir)

    @property
    def supported_providers(self) -> list:
        """Get a list of supported cloud providers"""
        return list(self._factories.keys())


# Create a singleton instance
manager = CloudAuditorManager()

# Register AWS factory
try:
    from .providers.aws import AWSAuditorFactory
    manager.register_factory('aws', AWSAuditorFactory())
except ImportError:
    pass

# Register Aliyun factory
try:
    from .providers.aliyun import AliyunAuditorFactory
    manager.register_factory('aliyun', AliyunAuditorFactory())
except ImportError:
    pass


