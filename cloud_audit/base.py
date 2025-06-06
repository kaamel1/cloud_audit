"""
Base classes and interfaces for cloud audit
"""
from abc import ABC, abstractmethod
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional


class CloudProvider(ABC):
    """Base class for cloud provider"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of the cloud provider"""
        pass


class CloudSession(ABC):
    """Base class for cloud session"""

    @abstractmethod
    def get_client(self, service_name: str) -> Any:
        """Get a client for the specified service"""
        pass

    @abstractmethod
    def get_account_id(self) -> str:
        """Get the current account ID"""
        pass

    @abstractmethod
    def get_enabled_regions(self) -> List[str]:
        """Get the available regions for the cloud provider"""
        pass


class CloudAuditor(ABC):
    """Base class for cloud auditor"""

    def __init__(self, session: CloudSession, output_dir: str = "output"):
        self.session = session
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def create_output_dirs(self) -> None:
        """Create output directory structure"""
        subdirs = ['assets']
        for subdir in subdirs:
            os.makedirs(os.path.join(self.output_dir, subdir), exist_ok=True)

    @abstractmethod
    def get_all_assets(self) -> Dict[str, Any]:
        """Get all assets from the cloud provider"""
        pass

    def save_json(self, data: Dict[str, Any], category: str, filename: str) -> None:
        """Save data as JSON file"""
        filepath = os.path.join(self.output_dir, category, f"{filename}_{self.timestamp}.json")
        with open(filepath, 'w') as f:
            json.dump(data, f, default=str, indent=2)

    def run_audit(self) -> None:
        """Run the complete audit"""
        self.create_output_dirs()

        # Collect and save assets data
        assets = self.get_all_assets()
        self.save_json(assets, 'assets', 'all_assets')


class CloudAuditorFactory(ABC):
    """Factory for creating cloud auditors"""

    @abstractmethod
    def create_session(self, **kwargs) -> CloudSession:
        """Create a session for the cloud provider"""
        pass

    @abstractmethod
    def create_auditor(self, session: CloudSession, output_dir: str = "output") -> CloudAuditor:
        """Create an auditor for the cloud provider"""
        pass


class CloudAuthenticator(ABC):
    """Base class for cloud authentication"""

    @abstractmethod
    def authenticate(self, **kwargs) -> CloudSession:
        """Authenticate with the cloud provider"""
        pass

    @abstractmethod
    def switch_role(self, session: CloudSession, role_arn: str, **kwargs) -> CloudSession:
        """Switch to a different role"""
        pass
