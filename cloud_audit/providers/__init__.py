"""
Cloud Providers Package

This package contains implementations for various cloud providers.
"""

# Import all cloud provider factories
try:
    from .aws import AWSAuditorFactory
except ImportError:
    AWSAuditorFactory = None

try:
    from .azure import AzureAuditorFactory
except ImportError:
    AzureAuditorFactory = None

try:
    from .aliyun import AliyunAuditorFactory
except ImportError:
    AliyunAuditorFactory = None

try:
    from .qcloud import QCloudAuditorFactory
except ImportError:
    QCloudAuditorFactory = None

# Registry of all available cloud providers
CLOUD_PROVIDERS = {}
if AWSAuditorFactory:
    CLOUD_PROVIDERS['aws'] = AWSAuditorFactory
if AzureAuditorFactory:
    CLOUD_PROVIDERS['azure'] = AzureAuditorFactory
if AliyunAuditorFactory:
    CLOUD_PROVIDERS['aliyun'] = AliyunAuditorFactory
if QCloudAuditorFactory:
    CLOUD_PROVIDERS['qcloud'] = QCloudAuditorFactory

__all__ = [
    'AWSAuditorFactory',
    'AzureAuditorFactory', 
    'AliyunAuditorFactory',
    'QCloudAuditorFactory',
    'CLOUD_PROVIDERS',
] 