"""Azure错误处理工具模块"""
import logging
from typing import Any, Callable, Optional
from functools import wraps

logger = logging.getLogger(__name__)


class AzureError(Exception):
    """Azure相关错误的基类"""
    pass


class AzureAuthenticationError(AzureError):
    """Azure认证错误"""
    pass


class AzurePermissionError(AzureError):
    """Azure权限错误"""
    pass


class AzureResourceNotFoundError(AzureError):
    """Azure资源未找到错误"""
    pass


class AzureServiceUnavailableError(AzureError):
    """Azure服务不可用错误"""
    pass


def handle_azure_exceptions(func: Callable) -> Callable:
    """
    Azure异常处理装饰器
    
    Args:
        func: 要装饰的函数
        
    Returns:
        Callable: 装饰后的函数
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_message = str(e).lower()
            
            # 根据错误消息分类异常
            if any(keyword in error_message for keyword in ['authentication', 'unauthorized', 'invalid credentials']):
                logger.error(f"Azure认证错误: {str(e)}")
                raise AzureAuthenticationError(f"Azure认证失败: {str(e)}")
            elif any(keyword in error_message for keyword in ['forbidden', 'access denied', 'permission']):
                logger.error(f"Azure权限错误: {str(e)}")
                raise AzurePermissionError(f"Azure权限不足: {str(e)}")
            elif any(keyword in error_message for keyword in ['not found', 'does not exist']):
                logger.error(f"Azure资源未找到: {str(e)}")
                raise AzureResourceNotFoundError(f"Azure资源未找到: {str(e)}")
            elif any(keyword in error_message for keyword in ['service unavailable', 'timeout', 'connection']):
                logger.error(f"Azure服务不可用: {str(e)}")
                raise AzureServiceUnavailableError(f"Azure服务不可用: {str(e)}")
            else:
                logger.error(f"Azure未知错误: {str(e)}")
                raise AzureError(f"Azure操作失败: {str(e)}")
    
    return wrapper


def safe_execute(func: Callable, default_value: Any = None, log_errors: bool = True) -> Any:
    """
    安全执行函数，捕获异常并返回默认值
    
    Args:
        func: 要执行的函数
        default_value: 发生异常时返回的默认值
        log_errors: 是否记录错误日志
        
    Returns:
        Any: 函数执行结果或默认值
    """
    try:
        return func()
    except Exception as e:
        if log_errors:
            logger.warning(f"函数执行失败，返回默认值: {str(e)}")
        return default_value


def retry_on_failure(max_retries: int = 3, delay: float = 1.0, backoff_factor: float = 2.0):
    """
    失败重试装饰器
    
    Args:
        max_retries: 最大重试次数
        delay: 初始延迟时间（秒）
        backoff_factor: 退避因子
        
    Returns:
        Callable: 装饰器函数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import time
            
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        logger.warning(f"函数 {func.__name__} 第 {attempt + 1} 次执行失败，{current_delay}秒后重试: {str(e)}")
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                    else:
                        logger.error(f"函数 {func.__name__} 重试 {max_retries} 次后仍然失败: {str(e)}")
            
            raise last_exception
        
        return wrapper
    return decorator


def log_azure_operation(operation_name: str):
    """
    Azure操作日志装饰器
    
    Args:
        operation_name: 操作名称
        
    Returns:
        Callable: 装饰器函数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(f"开始执行Azure操作: {operation_name}")
            try:
                result = func(*args, **kwargs)
                logger.info(f"Azure操作完成: {operation_name}")
                return result
            except Exception as e:
                logger.error(f"Azure操作失败: {operation_name}, 错误: {str(e)}")
                raise
        
        return wrapper
    return decorator


def validate_azure_resource_id(resource_id: str) -> bool:
    """
    验证Azure资源ID格式
    
    Args:
        resource_id: Azure资源ID
        
    Returns:
        bool: 是否为有效的Azure资源ID
    """
    if not resource_id or not isinstance(resource_id, str):
        return False
    
    # Azure资源ID的基本格式: /subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{resource-provider}/{resource-type}/{resource-name}
    parts = resource_id.split('/')
    
    # 至少应该有8个部分（包括空字符串）
    if len(parts) < 8:
        return False
    
    # 检查基本结构
    if (parts[0] != '' or 
        parts[1] != 'subscriptions' or 
        parts[3] != 'resourceGroups' or 
        parts[5] != 'providers'):
        return False
    
    return True


def extract_resource_group_from_id(resource_id: str) -> Optional[str]:
    """
    从Azure资源ID中提取资源组名称
    
    Args:
        resource_id: Azure资源ID
        
    Returns:
        Optional[str]: 资源组名称，如果提取失败则返回None
    """
    if not validate_azure_resource_id(resource_id):
        return None
    
    try:
        parts = resource_id.split('/')
        return parts[4]  # 资源组名称在第5个位置（索引4）
    except (IndexError, AttributeError):
        return None


def extract_subscription_from_id(resource_id: str) -> Optional[str]:
    """
    从Azure资源ID中提取订阅ID
    
    Args:
        resource_id: Azure资源ID
        
    Returns:
        Optional[str]: 订阅ID，如果提取失败则返回None
    """
    if not validate_azure_resource_id(resource_id):
        return None
    
    try:
        parts = resource_id.split('/')
        return parts[2]  # 订阅ID在第3个位置（索引2）
    except (IndexError, AttributeError):
        return None 