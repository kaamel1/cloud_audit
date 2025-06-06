"""阿里云监控资源处理模块，负责获取云监控、告警规则等资源信息。"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class MonitoringAssetCollector:
    """阿里云监控资源收集器"""

    def __init__(self, session):
        """
        初始化监控资源收集器

        Args:
            session: 阿里云会话对象
        """
        self.session = session
        # 初始化云监控客户端
        self.cms_client = session.get_client('cms')

    def get_alarm_rules(self) -> List[Dict[str, Any]]:
        """
        获取云监控告警规则信息

        Returns:
            List[Dict[str, Any]]: 告警规则列表
        """
        logger.info("获取云监控告警规则信息")
        rules = []

        try:
            # 导入阿里云云监控SDK请求模块
            from aliyunsdkcms.request.v20190101 import DescribeMetricRuleListRequest
            
            # 创建请求对象
            request = DescribeMetricRuleListRequest.DescribeMetricRuleListRequest()
            request.set_accept_format('json')
            # 尝试不同的分页设置方法
            try:
                request.set_PageSize(100)
                request.set_Page(1)
            except AttributeError:
                try:
                    request.set_PageSize(100)
                    # 有些API可能不需要设置页码，默认从第一页开始
                    pass
                except AttributeError:
                    # 如果都不行，就不设置分页参数
                    pass
            
            # 执行请求
            response = self.cms_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理告警规则数据
            alarms = response_dict.get('Alarms', {})
            alarm_list = alarms.get('Alarm', []) if isinstance(alarms, dict) else alarms
            
            for rule in alarm_list:
                rule_info = {
                    'rule_id': rule.get('RuleId'),
                    'name': rule.get('RuleName'),
                    'namespace': rule.get('Namespace'),
                    'metric_name': rule.get('MetricName'),
                    'dimensions': rule.get('Dimensions'),
                    'period': rule.get('Period'),
                    'statistics': rule.get('Statistics'),
                    'comparison_operator': rule.get('ComparisonOperator'),
                    'threshold': rule.get('Threshold'),
                    'evaluation_count': rule.get('EvaluationCount'),
                    'state': rule.get('State'),
                    'enable_state': rule.get('EnableState'),
                    'silence_time': rule.get('SilenceTime'),
                    'notify_type': rule.get('NotifyType'),
                    'webhook': rule.get('Webhook'),
                    'group_id': rule.get('GroupId'),
                    'group_name': rule.get('GroupName'),
                    'resource_group_id': rule.get('ResourceGroupId'),
                    'mail_subject': rule.get('MailSubject'),
                }
                rules.append(rule_info)
                
            # 处理分页 - 简化处理，只获取第一页数据
            # 因为不同版本的SDK分页方法可能不同，为了稳定性暂时只获取第一页
            logger.info(f"获取到第一页告警规则数据，共 {len(rules)} 条")
                    
        except Exception as e:
            logger.error(f"获取云监控告警规则信息失败: {str(e)}")

        return rules

    def get_alarm_contacts(self) -> List[Dict[str, Any]]:
        """
        获取云监控告警联系人信息

        Returns:
            List[Dict[str, Any]]: 告警联系人列表
        """
        logger.info("获取云监控告警联系人信息")
        contacts = []

        try:
            # 导入阿里云云监控SDK请求模块
            from aliyunsdkcms.request.v20190101 import DescribeContactListRequest
            
            # 创建请求对象
            request = DescribeContactListRequest.DescribeContactListRequest()
            request.set_accept_format('json')
            # 尝试不同的分页设置方法
            try:
                request.set_PageSize(100)
                request.set_Page(1)
            except AttributeError:
                try:
                    request.set_PageSize(100)
                    # 有些API可能不需要设置页码，默认从第一页开始
                    pass
                except AttributeError:
                    # 如果都不行，就不设置分页参数
                    pass
            
            # 执行请求
            response = self.cms_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理告警联系人数据
            contacts_data = response_dict.get('Contacts', [])
            if isinstance(contacts_data, dict):
                contacts_data = contacts_data.get('Contact', [])
            
            for contact in contacts_data:
                contact_info = {
                    'name': contact.get('Name'),
                    'desc': contact.get('Desc'),
                    'channels': {
                        'mail': contact.get('Channels', {}).get('Mail'),
                        'sms': contact.get('Channels', {}).get('SMS'),
                        'webhook': contact.get('Channels', {}).get('Webhook'),
                        'dingtalk': contact.get('Channels', {}).get('DingTalk'),
                    },
                    'create_time': contact.get('CreateTime'),
                    'update_time': contact.get('UpdateTime'),
                }
                contacts.append(contact_info)
                
            logger.info(f"获取到告警联系人数据，共 {len(contacts)} 个")
                    
        except Exception as e:
            logger.error(f"获取云监控告警联系人信息失败: {str(e)}")

        return contacts

    def get_alarm_contact_groups(self) -> List[Dict[str, Any]]:
        """
        获取云监控告警联系组信息

        Returns:
            List[Dict[str, Any]]: 告警联系组列表
        """
        logger.info("获取云监控告警联系组信息")
        contact_groups = []

        try:
            # 导入阿里云云监控SDK请求模块
            from aliyunsdkcms.request.v20190101 import DescribeContactGroupListRequest
            
            # 创建请求对象
            request = DescribeContactGroupListRequest.DescribeContactGroupListRequest()
            request.set_accept_format('json')
            # 尝试不同的分页设置方法
            try:
                request.set_PageSize(100)
                request.set_Page(1)
            except AttributeError:
                try:
                    request.set_PageSize(100)
                    # 有些API可能不需要设置页码，默认从第一页开始
                    pass
                except AttributeError:
                    # 如果都不行，就不设置分页参数
                    pass
            
            # 执行请求
            response = self.cms_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 添加调试信息
            logger.debug(f"告警联系组API响应类型: {type(response_dict)}")
            
            # 检查响应是否为字典
            if not isinstance(response_dict, dict):
                logger.error(f"告警联系组API响应不是字典格式，实际类型: {type(response_dict)}, 内容: {response_dict}")
                return contact_groups
            
            # 处理告警联系组数据
            groups_data = response_dict.get('ContactGroups', [])
            if isinstance(groups_data, dict):
                groups_data = groups_data.get('ContactGroup', [])
            elif isinstance(groups_data, str):
                logger.error(f"告警联系组数据是字符串格式，无法处理: {groups_data}")
                return contact_groups
            
            # 确保groups_data是列表
            if not isinstance(groups_data, list):
                logger.warning(f"告警联系组数据不是列表格式，尝试转换: {type(groups_data)}")
                if isinstance(groups_data, dict):
                    groups_data = [groups_data]
                else:
                    groups_data = []
            
            for group in groups_data:
                # 确保group是字典
                if not isinstance(group, dict):
                    logger.warning(f"告警联系组项不是字典格式，跳过: {type(group)}, 内容: {group}")
                    continue
                    
                group_info = {
                    'name': group.get('Name'),
                    'desc': group.get('Desc'),
                    'contacts': group.get('Contacts', {}).get('Contact', []) if isinstance(group.get('Contacts'), dict) else [],
                    'enable_subscribed': group.get('EnableSubscribed'),
                    'enable_weekly_report': group.get('EnableWeeklyReport'),
                    'create_time': group.get('CreateTime'),
                    'update_time': group.get('UpdateTime'),
                }
                contact_groups.append(group_info)
                
            logger.info(f"获取到告警联系组数据，共 {len(contact_groups)} 个")
                    
        except Exception as e:
            logger.error(f"获取云监控告警联系组信息失败: {str(e)}")
            logger.debug(f"错误详情: {type(e).__name__}: {str(e)}")

        return contact_groups

    def get_site_monitors(self) -> List[Dict[str, Any]]:
        """
        获取云监控站点监控信息

        Returns:
            List[Dict[str, Any]]: 站点监控列表
        """
        logger.info("获取云监控站点监控信息")
        site_monitors = []

        try:
            # 导入阿里云云监控SDK请求模块
            from aliyunsdkcms.request.v20190101 import DescribeSiteMonitorListRequest
            
            # 创建请求对象
            request = DescribeSiteMonitorListRequest.DescribeSiteMonitorListRequest()
            request.set_accept_format('json')
            # 尝试不同的分页设置方法
            try:
                request.set_PageSize(100)
                request.set_Page(1)
            except AttributeError:
                try:
                    request.set_PageSize(100)
                    # 有些API可能不需要设置页码，默认从第一页开始
                    pass
                except AttributeError:
                    # 如果都不行，就不设置分页参数
                    pass
            
            # 执行请求
            response = self.cms_client.do_action_with_exception(request)
            response_dict = self.session.parse_response(response)
            
            # 处理站点监控数据
            monitors_data = response_dict.get('SiteMonitors', [])
            if isinstance(monitors_data, dict):
                monitors_data = monitors_data.get('SiteMonitor', [])
            
            for monitor in monitors_data:
                monitor_info = {
                    'id': monitor.get('Id'),
                    'task_name': monitor.get('TaskName'),
                    'task_type': monitor.get('TaskType'),
                    'address': monitor.get('Address'),
                    'task_state': monitor.get('TaskState'),
                    'interval': monitor.get('Interval'),
                    'isp_cities': monitor.get('IspCities', {}).get('IspCity', []),
                    'create_time': monitor.get('CreateTime'),
                    'update_time': monitor.get('UpdateTime'),
                    'options': monitor.get('Options'),
                }
                site_monitors.append(monitor_info)
                
            logger.info(f"获取到站点监控数据，共 {len(site_monitors)} 个")
                    
        except Exception as e:
            logger.error(f"获取云监控站点监控信息失败: {str(e)}")

        return site_monitors

    def get_all_monitoring_assets(self) -> Dict[str, Any]:
        """
        获取所有监控资源

        Returns:
            Dict[str, Any]: 所有监控资源
        """
        logger.info("获取所有阿里云监控资源")
        
        # 获取各类监控资源
        alarm_rules = self.get_alarm_rules()
        # alarm_contacts = self.get_alarm_contacts()
        # alarm_contact_groups = self.get_alarm_contact_groups()
        site_monitors = self.get_site_monitors()
        
        # 组织返回结果
        monitoring_assets = {
            'alarm_rules': {rule['rule_id']: rule for rule in alarm_rules if rule.get('rule_id')},
            # 'alarm_contacts': {contact['name']: contact for contact in alarm_contacts if contact.get('name')},
            # 'alarm_contact_groups': {group['name']: group for group in alarm_contact_groups if group.get('name')},
            'site_monitors': {monitor['id']: monitor for monitor in site_monitors if monitor.get('id')},
        }
        
        # logger.info(f"已获取 {len(alarm_rules)} 条告警规则, {len(alarm_contacts)} 个告警联系人, {len(alarm_contact_groups)} 个告警联系组, {len(site_monitors)} 个站点监控")
        logger.info(f"已获取 {len(alarm_rules)} 条告警规则, {len(site_monitors)} 个站点监控")
        return monitoring_assets 