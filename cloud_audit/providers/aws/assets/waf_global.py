"""
AWS WAF全局资源处理模块，负责获取WAF Web ACL、规则组、IP集合等Web应用防火墙全局资源信息。
WAF是AWS的全局服务，在不同区域获取到的数据是一致的。
"""
import boto3
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class WAFGlobalAssetCollector:
    """AWS WAF全局资源收集器"""

    def __init__(self, session):
        """
        初始化WAF全局资源收集器

        Args:
            session: AWS会话对象
        """
        self.session = session
        self.wafv2_client = session.get_client('wafv2')

    def get_web_acls(self) -> List[Dict[str, Any]]:
        """
        获取WAF Web ACL信息

        Returns:
            List[Dict[str, Any]]: Web ACL列表
        """
        logger.info("获取WAF Web ACL信息")
        all_web_acls = []

        try:
            # 获取CloudFront范围的Web ACL
            cloudfront_acls = self._get_web_acls_by_scope('CLOUDFRONT')
            all_web_acls.extend(cloudfront_acls)
            
            # 获取区域范围的Web ACL  
            regional_acls = self._get_web_acls_by_scope('REGIONAL')
            all_web_acls.extend(regional_acls)

        except Exception as e:
            logger.error(f"获取WAF Web ACL信息失败: {str(e)}")

        return all_web_acls

    def _get_web_acls_by_scope(self, scope: str) -> List[Dict[str, Any]]:
        """
        根据范围获取Web ACL
        
        Args:
            scope: 'CLOUDFRONT' 或 'REGIONAL'
            
        Returns:
            List[Dict[str, Any]]: 指定范围的Web ACL列表
        """
        web_acls = []
        
        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.wafv2_client.list_web_acls(Scope=scope, NextMarker=next_marker)
                else:
                    response = self.wafv2_client.list_web_acls(Scope=scope)
                
                for acl in response.get('WebACLs', []):
                    # 获取Web ACL详细信息
                    acl_detail = self.wafv2_client.get_web_acl(
                        Name=acl['Name'],
                        Scope=scope,
                        Id=acl['Id']
                    )
                    
                    # 获取关联的资源
                    associated_resources = []
                    try:
                        if scope == 'REGIONAL':
                            # 区域Web ACL可以关联ALB、API Gateway等
                            resources_next_marker = None
                            while True:
                                if resources_next_marker:
                                    resources_response = self.wafv2_client.list_resources_for_web_acl(
                                        WebACLArn=acl['ARN'],
                                        ResourceType='APPLICATION_LOAD_BALANCER',
                                        NextMarker=resources_next_marker
                                    )
                                else:
                                    resources_response = self.wafv2_client.list_resources_for_web_acl(
                                        WebACLArn=acl['ARN'],
                                        ResourceType='APPLICATION_LOAD_BALANCER'
                                    )
                                
                                associated_resources.extend(resources_response.get('ResourceArns', []))
                                
                                if 'NextMarker' in resources_response:
                                    resources_next_marker = resources_response['NextMarker']
                                else:
                                    break
                        elif scope == 'CLOUDFRONT':
                            # CloudFront Web ACL关联的资源
                            resources_next_marker = None
                            while True:
                                if resources_next_marker:
                                    resources_response = self.wafv2_client.list_resources_for_web_acl(
                                        WebACLArn=acl['ARN'],
                                        NextMarker=resources_next_marker
                                    )
                                else:
                                    resources_response = self.wafv2_client.list_resources_for_web_acl(WebACLArn=acl['ARN'])
                                
                                associated_resources.extend(resources_response.get('ResourceArns', []))
                                
                                if 'NextMarker' in resources_response:
                                    resources_next_marker = resources_response['NextMarker']
                                else:
                                    break
                    except Exception as e:
                        logger.warning(f"获取Web ACL {acl['Name']} 关联资源失败: {str(e)}")
                    
                    # 获取标签
                    tags = []
                    try:
                        tags_response = self.wafv2_client.list_tags_for_resource(
                            ResourceARN=acl['ARN']
                        )
                        tags = tags_response.get('TagList', {}).get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取Web ACL {acl['Name']} 标签失败: {str(e)}")
                    
                    web_acl_info = {
                        'Id': acl_detail['WebACL'].get('Id'),
                        'Name': acl_detail['WebACL'].get('Name'),
                        'ARN': acl_detail['WebACL'].get('ARN'),
                        'Scope': scope,
                        'DefaultAction': acl_detail['WebACL'].get('DefaultAction'),
                        'Rules': acl_detail['WebACL'].get('Rules', []),
                        'VisibilityConfig': acl_detail['WebACL'].get('VisibilityConfig'),
                        'Capacity': acl_detail['WebACL'].get('Capacity'),
                        'PreProcessFirewallManagerRuleGroups': acl_detail['WebACL'].get('PreProcessFirewallManagerRuleGroups', []),
                        'PostProcessFirewallManagerRuleGroups': acl_detail['WebACL'].get('PostProcessFirewallManagerRuleGroups', []),
                        'ManagedByFirewallManager': acl_detail['WebACL'].get('ManagedByFirewallManager'),
                        'LabelNamespace': acl_detail['WebACL'].get('LabelNamespace'),
                        'AssociatedResources': associated_resources,
                        'Tags': tags
                    }
                    web_acls.append(web_acl_info)
                
                if 'NextMarker' in response:
                    next_marker = response['NextMarker']
                else:
                    break

        except Exception as e:
            logger.error(f"获取范围 {scope} 的Web ACL失败: {str(e)}")
            
        return web_acls

    def get_rule_groups(self) -> List[Dict[str, Any]]:
        """
        获取WAF规则组信息

        Returns:
            List[Dict[str, Any]]: 规则组列表
        """
        logger.info("获取WAF规则组信息")
        all_rule_groups = []

        try:
            # 获取CloudFront范围的规则组
            cloudfront_groups = self._get_rule_groups_by_scope('CLOUDFRONT')
            all_rule_groups.extend(cloudfront_groups)
            
            # 获取区域范围的规则组
            regional_groups = self._get_rule_groups_by_scope('REGIONAL')
            all_rule_groups.extend(regional_groups)

        except Exception as e:
            logger.error(f"获取WAF规则组信息失败: {str(e)}")

        return all_rule_groups

    def _get_rule_groups_by_scope(self, scope: str) -> List[Dict[str, Any]]:
        """
        根据范围获取规则组
        
        Args:
            scope: 'CLOUDFRONT' 或 'REGIONAL'
            
        Returns:
            List[Dict[str, Any]]: 指定范围的规则组列表
        """
        rule_groups = []
        
        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.wafv2_client.list_rule_groups(Scope=scope, NextMarker=next_marker)
                else:
                    response = self.wafv2_client.list_rule_groups(Scope=scope)
                
                for group in response.get('RuleGroups', []):
                    # 获取规则组详细信息
                    group_detail = self.wafv2_client.get_rule_group(
                        Name=group['Name'],
                        Scope=scope,
                        Id=group['Id']
                    )
                    
                    # 获取标签
                    tags = []
                    try:
                        tags_response = self.wafv2_client.list_tags_for_resource(
                            ResourceARN=group['ARN']
                        )
                        tags = tags_response.get('TagList', {}).get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取规则组 {group['Name']} 标签失败: {str(e)}")
                    
                    rule_group_info = {
                        'Id': group_detail['RuleGroup'].get('Id'),
                        'Name': group_detail['RuleGroup'].get('Name'),
                        'ARN': group_detail['RuleGroup'].get('ARN'),
                        'Scope': scope,
                        'Capacity': group_detail['RuleGroup'].get('Capacity'),
                        'Rules': group_detail['RuleGroup'].get('Rules', []),
                        'VisibilityConfig': group_detail['RuleGroup'].get('VisibilityConfig'),
                        'LabelNamespace': group_detail['RuleGroup'].get('LabelNamespace'),
                        'Tags': tags
                    }
                    rule_groups.append(rule_group_info)
                
                if 'NextMarker' in response:
                    next_marker = response['NextMarker']
                else:
                    break
                    
        except Exception as e:
            logger.error(f"获取范围 {scope} 的规则组失败: {str(e)}")
            
        return rule_groups

    def get_ip_sets(self) -> List[Dict[str, Any]]:
        """
        获取WAF IP集合信息

        Returns:
            List[Dict[str, Any]]: IP集合列表
        """
        logger.info("获取WAF IP集合信息")
        all_ip_sets = []

        try:
            # 获取CloudFront范围的IP集合
            cloudfront_ip_sets = self._get_ip_sets_by_scope('CLOUDFRONT')
            all_ip_sets.extend(cloudfront_ip_sets)
            
            # 获取区域范围的IP集合
            regional_ip_sets = self._get_ip_sets_by_scope('REGIONAL')
            all_ip_sets.extend(regional_ip_sets)

        except Exception as e:
            logger.error(f"获取WAF IP集合信息失败: {str(e)}")

        return all_ip_sets

    def _get_ip_sets_by_scope(self, scope: str) -> List[Dict[str, Any]]:
        """
        根据范围获取IP集合
        
        Args:
            scope: 'CLOUDFRONT' 或 'REGIONAL'
            
        Returns:
            List[Dict[str, Any]]: 指定范围的IP集合列表
        """
        ip_sets = []
        
        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.wafv2_client.list_ip_sets(Scope=scope, NextMarker=next_marker)
                else:
                    response = self.wafv2_client.list_ip_sets(Scope=scope)
                
                for ip_set in response.get('IPSets', []):
                    # 获取IP集合详细信息
                    ip_set_detail = self.wafv2_client.get_ip_set(
                        Name=ip_set['Name'],
                        Scope=scope,
                        Id=ip_set['Id']
                    )
                    
                    # 获取标签
                    tags = []
                    try:
                        tags_response = self.wafv2_client.list_tags_for_resource(
                            ResourceARN=ip_set['ARN']
                        )
                        tags = tags_response.get('TagList', {}).get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取IP集合 {ip_set['Name']} 标签失败: {str(e)}")
                    
                    ip_set_info = {
                        'Id': ip_set_detail['IPSet'].get('Id'),
                        'Name': ip_set_detail['IPSet'].get('Name'),
                        'ARN': ip_set_detail['IPSet'].get('ARN'),
                        'Scope': scope,
                        'IPAddressVersion': ip_set_detail['IPSet'].get('IPAddressVersion'),
                        'Addresses': ip_set_detail['IPSet'].get('Addresses', []),
                        'Description': ip_set_detail['IPSet'].get('Description'),
                        'Tags': tags
                    }
                    ip_sets.append(ip_set_info)
                
                if 'NextMarker' in response:
                    next_marker = response['NextMarker']
                else:
                    break
                    
        except Exception as e:
            logger.error(f"获取范围 {scope} 的IP集合失败: {str(e)}")
            
        return ip_sets

    def get_regex_pattern_sets(self) -> List[Dict[str, Any]]:
        """
        获取WAF正则表达式模式集合信息

        Returns:
            List[Dict[str, Any]]: 正则表达式模式集合列表
        """
        logger.info("获取WAF正则表达式模式集合信息")
        all_regex_pattern_sets = []

        try:
            # 获取CloudFront范围的正则表达式模式集合
            cloudfront_regex_sets = self._get_regex_pattern_sets_by_scope('CLOUDFRONT')
            all_regex_pattern_sets.extend(cloudfront_regex_sets)
            
            # 获取区域范围的正则表达式模式集合
            regional_regex_sets = self._get_regex_pattern_sets_by_scope('REGIONAL')
            all_regex_pattern_sets.extend(regional_regex_sets)

        except Exception as e:
            logger.error(f"获取WAF正则表达式模式集合信息失败: {str(e)}")

        return all_regex_pattern_sets

    def _get_regex_pattern_sets_by_scope(self, scope: str) -> List[Dict[str, Any]]:
        """
        根据范围获取正则表达式模式集合
        
        Args:
            scope: 'CLOUDFRONT' 或 'REGIONAL'
            
        Returns:
            List[Dict[str, Any]]: 指定范围的正则表达式模式集合列表
        """
        regex_pattern_sets = []
        
        try:
            next_marker = None
            while True:
                if next_marker:
                    response = self.wafv2_client.list_regex_pattern_sets(Scope=scope, NextMarker=next_marker)
                else:
                    response = self.wafv2_client.list_regex_pattern_sets(Scope=scope)
                
                for regex_set in response.get('RegexPatternSets', []):
                    # 获取正则表达式模式集合详细信息
                    regex_set_detail = self.wafv2_client.get_regex_pattern_set(
                        Name=regex_set['Name'],
                        Scope=scope,
                        Id=regex_set['Id']
                    )
                    
                    # 获取标签
                    tags = []
                    try:
                        tags_response = self.wafv2_client.list_tags_for_resource(
                            ResourceARN=regex_set['ARN']
                        )
                        tags = tags_response.get('TagList', {}).get('Tags', [])
                    except Exception as e:
                        logger.warning(f"获取正则表达式模式集合 {regex_set['Name']} 标签失败: {str(e)}")
                    
                    regex_pattern_set_info = {
                        'Id': regex_set_detail['RegexPatternSet'].get('Id'),
                        'Name': regex_set_detail['RegexPatternSet'].get('Name'),
                        'ARN': regex_set_detail['RegexPatternSet'].get('ARN'),
                        'Scope': scope,
                        'Description': regex_set_detail['RegexPatternSet'].get('Description'),
                        'RegularExpressionList': regex_set_detail['RegexPatternSet'].get('RegularExpressionList', []),
                        'Tags': tags
                    }
                    regex_pattern_sets.append(regex_pattern_set_info)
                
                if 'NextMarker' in response:
                    next_marker = response['NextMarker']
                else:
                    break
                    
        except Exception as e:
            logger.error(f"获取范围 {scope} 的正则表达式模式集合失败: {str(e)}")
            
        return regex_pattern_sets

    def get_all_waf_global_assets(self) -> Dict[str, Any]:
        """
        获取所有WAF全局资源

        Returns:
            Dict[str, Any]: 所有WAF全局资源
        """
        logger.info("开始收集所有WAF全局资源")
        
        assets = {
            'web_acls': self.get_web_acls(),
            'rule_groups': self.get_rule_groups(),
            'ip_sets': self.get_ip_sets(),
            'regex_pattern_sets': self.get_regex_pattern_sets()
        }
        
        logger.info("WAF全局资源收集完成")
        return assets 