"""阿里云错误处理工具模块"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def handle_aliyun_error(error: Exception, service_name: str, operation: str, logger_instance: logging.Logger = None) -> Dict[str, Any]:
    """
    处理阿里云API错误，提供统一的错误分类和建议
    
    Args:
        error: 异常对象
        service_name: 服务名称，如'域名', 'DNS', 'OSS'等
        operation: 操作名称，如'获取域名信息', '获取DNS记录'等
        logger_instance: 日志记录器实例，如果不提供则使用默认logger
        
    Returns:
        Dict[str, Any]: 包含错误类型、建议等信息的字典
    """
    if logger_instance is None:
        logger_instance = logger
        
    error_msg = str(error)
    result = {
        'error_type': 'unknown',
        'suggestion': None,
        'should_retry': False,
        'is_permission_error': False,
        'is_auth_error': False
    }
    
    # 权限相关错误
    if 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg:
        result['error_type'] = 'permission_denied'
        result['is_permission_error'] = True
        logger_instance.warning(f"{service_name}服务访问被拒绝: 当前RAM用户没有{service_name}服务权限，或该API不支持RAM用户访问")
        logger_instance.warning(f"建议: 请使用主账号访问密钥，或为RAM用户添加{service_name}服务相关权限")
        logger_instance.debug(f"详细错误信息: {error_msg}")
        result['suggestion'] = f"请使用主账号访问密钥，或为RAM用户添加{service_name}服务相关权限"
        
    # 认证失败
    elif 'InvalidAccessKeyId' in error_msg or 'does not exist in our records' in error_msg:
        result['error_type'] = 'authentication_failed'
        result['is_auth_error'] = True
        logger_instance.error(f"认证失败: 访问密钥无效或不存在")
        logger_instance.debug(f"详细错误信息: {error_msg}")
        result['suggestion'] = "请检查访问密钥ID和密钥是否正确"
        
    # 访问频率限制
    elif 'Throttling' in error_msg or 'RequestLimitExceeded' in error_msg:
        result['error_type'] = 'rate_limit'
        result['should_retry'] = True
        logger_instance.warning(f"{operation}请求频率过高，触发限流")
        logger_instance.info(f"建议: 稍后重试或降低请求频率")
        result['suggestion'] = "稍后重试或降低请求频率"
        
    # 网络连接错误
    elif 'Failed to resolve' in error_msg or 'NameResolutionError' in error_msg or 'ConnectionError' in error_msg:
        result['error_type'] = 'network_error'
        result['should_retry'] = True
        logger_instance.error(f"{operation}网络连接失败: {error_msg}")
        result['suggestion'] = "检查网络连接或稍后重试"
        
    # 资源不存在
    elif 'NotFound' in error_msg or 'does not exist' in error_msg:
        result['error_type'] = 'resource_not_found'
        logger_instance.warning(f"{operation}失败: 资源不存在")
        logger_instance.debug(f"详细错误信息: {error_msg}")
        result['suggestion'] = "请检查资源名称是否正确"
        
    # 参数错误
    elif 'InvalidParameter' in error_msg or 'MissingParameter' in error_msg:
        result['error_type'] = 'parameter_error'
        logger_instance.error(f"{operation}失败: 参数错误")
        logger_instance.debug(f"详细错误信息: {error_msg}")
        result['suggestion'] = "请检查API调用参数是否正确"
        
    # 其他错误
    else:
        result['error_type'] = 'unknown'
        logger_instance.error(f"{operation}失败: {error_msg}")
        
    return result

def is_permission_error(error: Exception) -> bool:
    """
    判断是否为权限相关错误
    
    Args:
        error: 异常对象
        
    Returns:
        bool: 是否为权限错误
    """
    error_msg = str(error)
    return 'Forbidden.RAM' in error_msg or 'not authorized' in error_msg

def is_auth_error(error: Exception) -> bool:
    """
    判断是否为认证相关错误
    
    Args:
        error: 异常对象
        
    Returns:
        bool: 是否为认证错误
    """
    error_msg = str(error)
    return 'InvalidAccessKeyId' in error_msg or 'does not exist in our records' in error_msg

def should_retry_error(error: Exception) -> bool:
    """
    判断错误是否应该重试
    
    Args:
        error: 异常对象
        
    Returns:
        bool: 是否应该重试
    """
    error_msg = str(error)
    retry_conditions = [
        'Throttling' in error_msg,
        'RequestLimitExceeded' in error_msg,
        'Failed to resolve' in error_msg,
        'NameResolutionError' in error_msg,
        'ConnectionError' in error_msg,
        'ServiceUnavailable' in error_msg,
        'InternalError' in error_msg
    ]
 