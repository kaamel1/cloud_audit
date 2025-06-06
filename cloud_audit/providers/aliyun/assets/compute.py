"""阿里云计算资源处理模块，负责获取ECS实例、函数计算等计算资源信息。"""
import logging
import json
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ComputeAssetCollector:
    """阿里云计算资源收集器"""

    def __init__(self, session):
        """
        初始化计算资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        self.ecs_client = session.get_client('ecs')
        self.fc_client = session.get_client('fc')  # 函数计算
        self.slb_client = session.get_client('slb')  # 负载均衡

    def get_ecs_instances(self) -> List[Dict[str, Any]]:
        """
        获取ECS实例信息

        Returns:
            List[Dict[str, Any]]: ECS实例列表
        """
        logger.info("获取ECS实例信息")
        instances = []

        try:
            # 打印当前会话的区域和AccessKey信息（部分掩码处理）
            logger.info(f"实际使用的区域: {self.session.region_id}")
            masked_ak = self.session.access_key_id[:4] + "****" + self.session.access_key_id[-4:] if len(self.session.access_key_id) > 8 else "***"
            logger.info(f"使用的AccessKey ID (掩码): {masked_ak}")
            
            # 尝试获取账号ID
            try:
                from aliyunsdksts.request.v20150401 import GetCallerIdentityRequest
                import json
                
                sts_client = self.session.get_client('sts')
                request = GetCallerIdentityRequest.GetCallerIdentityRequest()
                response = sts_client.do_action_with_exception(request)
                
                result = json.loads(response)
                account_id = result.get('AccountId', 'unknown')
                logger.info(f"当前操作的账号: {account_id}")
            except Exception as e:
                logger.warning(f"获取账号ID失败: {str(e)}")
            
            # 导入阿里云ECS SDK请求模块
            from aliyunsdkecs.request.v20140526 import DescribeInstancesRequest
            
            # 创建请求对象
            request = DescribeInstancesRequest.DescribeInstancesRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 100
            request.set_PageSize(page_size)
            
            # 记录区域信息
            logger.info(f"正在使用区域: {self.session.region_id} 获取ECS实例")
            
            # 分页获取所有实例
            page_number = 1
            total_instances = []
            
            while True:
                request.set_PageNumber(page_number)
                try:
                    logger.info(f"正在请求ECS实例数据，页码: {page_number}")
                    response = self.ecs_client.do_action_with_exception(request)
                    response_json = json.loads(response)
                    
                    # 输出API响应详情用于调试
                    logger.info(f"ECS API响应 - 页面{page_number}: 总数={response_json.get('TotalCount', 0)}, 当前页实例数={len(response_json.get('Instances', {}).get('Instance', []))}")
                    logger.info(f"响应内容: {response_json.keys()}")
                    
                    current_instances = response_json.get('Instances', {}).get('Instance', [])
                    total_instances.extend(current_instances)
                    
                    # 判断是否还有更多页
                    total_count = response_json.get('TotalCount', 0)
                    if page_number * page_size >= total_count:
                        break
                        
                    page_number += 1
                except Exception as inner_e:
                    logger.error(f"请求ECS实例数据时发生错误 (页码 {page_number}): {str(inner_e)}")
                    break
            
            logger.info(f"当前区域 {self.session.region_id} 共获取到 {len(total_instances)} 个ECS实例")
            
            # 处理实例数据
            for instance in total_instances:
                instance_info = {
                    'InstanceId': instance.get('InstanceId'),
                    'InstanceName': instance.get('InstanceName'),
                    'InstanceType': instance.get('InstanceType'),
                    'Status': instance.get('Status'),
                    'PrivateIpAddress': instance.get('VpcAttributes', {}).get('PrivateIpAddress', {}).get('IpAddress', []),
                    'PublicIpAddress': instance.get('PublicIpAddress', {}).get('IpAddress', []),
                    'CreationTime': instance.get('CreationTime'),
                    'VpcId': instance.get('VpcAttributes', {}).get('VpcId'),
                    'VSwitchId': instance.get('VpcAttributes', {}).get('VSwitchId'),
                    'SecurityGroupIds': instance.get('SecurityGroupIds', {}).get('SecurityGroupId', []),
                    'Tags': instance.get('Tags', {}).get('Tag', []),
                }
                instances.append(instance_info)
                
        except ImportError as e:
            logger.error(f"导入阿里云ECS SDK模块失败: {str(e)}")
            logger.error("请确保已安装阿里云ECS SDK: pip install aliyun-python-sdk-ecs")
        except Exception as e:
            logger.error(f"获取ECS实例信息失败: {str(e)}")
            import traceback
            logger.error(f"错误详情: {traceback.format_exc()}")
        
        return instances

    def get_function_compute(self) -> List[Dict[str, Any]]:
        """
        获取函数计算资源

        Returns:
            List[Dict[str, Any]]: 函数计算资源列表
        """
        logger.info("获取函数计算资源")
        functions = []

        try:
            # 注意：阿里云函数计算使用的是FC SDK，而不是通用的aliyunsdk模式
            # 这里需要使用FC SDK的客户端
            # 由于FC SDK的调用方式与其他服务不同，这里提供一个框架
            
            # 获取所有服务
            services = []  # 这里应该调用FC SDK获取所有服务
            
            # 遍历每个服务，获取其中的函数
            for service in services:
                service_name = service.get('serviceName')
                service_functions = []  # 这里应该调用FC SDK获取服务中的所有函数
                
                for func in service_functions:
                    function_info = {
                        'ServiceName': service_name,
                        'FunctionName': func.get('functionName'),
                        'Description': func.get('description'),
                        'Runtime': func.get('runtime'),
                        'Handler': func.get('handler'),
                        'MemorySize': func.get('memorySize'),
                        'Timeout': func.get('timeout'),
                        'CreatedTime': func.get('createdTime'),
                        'LastModifiedTime': func.get('lastModifiedTime'),
                    }
                    functions.append(function_info)
                    
        except Exception as e:
            logger.error(f"获取函数计算资源失败: {str(e)}")
        
        return functions

    def get_slb_instances(self) -> List[Dict[str, Any]]:
        """
        获取负载均衡实例信息

        Returns:
            List[Dict[str, Any]]: 负载均衡实例列表
        """
        logger.info("获取负载均衡实例信息")
        slb_instances = []

        try:
            # 导入阿里云SLB SDK请求模块
            try:
                from aliyunsdkslb.request.v20140515 import DescribeLoadBalancersRequest
            except ImportError:
                logger.warning(
                    "阿里云SLB SDK未安装，跳过负载均衡实例收集。\n"
                    "如需收集负载均衡数据，请安装：pip install aliyun-python-sdk-slb"
                )
                return slb_instances
            
            # 创建请求对象
            request = DescribeLoadBalancersRequest.DescribeLoadBalancersRequest()
            request.set_accept_format('json')
            
            # 设置分页参数
            page_size = 100
            request.set_PageSize(page_size)
            
            # 分页获取所有SLB实例
            page_number = 1
            total_slbs = []
            
            while True:
                request.set_PageNumber(page_number)
                response = self.slb_client.do_action_with_exception(request)
                response_json = json.loads(response)
                
                current_slbs = response_json.get('LoadBalancers', {}).get('LoadBalancer', [])
                total_slbs.extend(current_slbs)
                
                # 判断是否还有更多页
                total_count = response_json.get('TotalCount', 0)
                if page_number * page_size >= total_count:
                    break
                    
                page_number += 1
            
            # 处理SLB实例数据
            for slb in total_slbs:
                slb_info = {
                    'LoadBalancerId': slb.get('LoadBalancerId'),
                    'LoadBalancerName': slb.get('LoadBalancerName'),
                    'LoadBalancerStatus': slb.get('LoadBalancerStatus'),
                    'Address': slb.get('Address'),
                    'AddressType': slb.get('AddressType'),
                    'NetworkType': slb.get('NetworkType'),
                    'VpcId': slb.get('VpcId'),
                    'VSwitchId': slb.get('VSwitchId'),
                    'CreateTime': slb.get('CreateTime'),
                    'RegionId': slb.get('RegionId'),
                    'AddressIPVersion': slb.get('AddressIPVersion'),
                }
                slb_instances.append(slb_info)
                
        except Exception as e:
            logger.error(f"获取负载均衡实例信息失败: {str(e)}")
        
        return slb_instances

    def get_all_compute_assets(self) -> Dict[str, Any]:
        """
        获取所有计算资源

        Returns:
            Dict[str, Any]: 所有计算资源
        """
        logger.info("获取所有阿里云计算资源")
        
        # 获取各类计算资源
        ecs_instances = self.get_ecs_instances()
        functions = self.get_function_compute()
        slb_instances = self.get_slb_instances()
        
        # 组织返回结果
        compute_assets = {
            'ecs': {instance['InstanceId']: instance for instance in ecs_instances},
            'function_compute': {func['FunctionName']: func for func in functions},
            'slb': {slb['LoadBalancerId']: slb for slb in slb_instances},
        }
        
        logger.info(f"已获取 {len(ecs_instances)} 个ECS实例, {len(functions)} 个函数计算资源, {len(slb_instances)} 个负载均衡实例")
        return compute_assets