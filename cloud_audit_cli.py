#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Audit CLI - A multi-cloud resource auditing tool
"""
import click
import logging
import os
from cloud_audit.factory import manager as cloud_manager
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cloud-audit')


@click.group()
def cli():
    """多云资源审计工具 - 收集云账号资源和权限信息"""
    pass

def merged_output_core(output_dir: str):
    """合并输出目录"""
    output_dir_path = f"output_all/{output_dir}"
    if not os.path.exists(output_dir_path):
        click.echo(f"输出目录 {output_dir_path} 不存在")
        return
    
    # 遍历output_dir_region目录下的所有子目录
    merged_assets = {
        'type': '',
        'global': {},
        'regions': {}
    }
    for regionDir in os.listdir(output_dir_path):
        print(regionDir)
        if regionDir == 'global':
            if os.path.exists(f'{output_dir_path}/{regionDir}/assets/all_assets_global.json'):
                with open(f'{output_dir_path}/{regionDir}/assets/all_assets_global.json', 'r') as f:
                    all_assets_global = json.loads(f.read())
                    merged_assets['type'] = all_assets_global.get('type').split('_')[0]
                    merged_assets['global'] = all_assets_global.get('assets')
        else:
            if os.path.exists(f'{output_dir_path}/{regionDir}/assets/all_assets.json'):
                with open(f'{output_dir_path}/{regionDir}/assets/all_assets.json', 'r') as f:
                    all_assets = json.loads(f.read())
                    merged_assets['regions'][regionDir] = all_assets.get('assets')

        with open(f'{output_dir_path}/all_assets_merged.json', 'w') as f:
            json.dump(merged_assets, f, indent=4)



@cli.command()
@click.option('--provider', type=click.Choice(cloud_manager.supported_providers), required=True,
              help='云服务提供商 (aws, aliyun, azure, qcloud)')
@click.option('--role-arn', help='要切换到的IAM角色ARN (仅AWS)')
@click.option('--profile', help='使用的配置文件名称')
@click.option('--access-key-id', help='访问密钥ID')
@click.option('--secret-access-key', help='访问密钥')
@click.option('--session-token', help='会话令牌（使用临时凭证时需要）')
@click.option('--external-id', help='角色切换时的External ID（如果需要）')
@click.option('--subscription-id', help='Azure订阅ID (仅Azure)')
@click.option('--tenant-id', help='Azure租户ID (仅Azure)')
@click.option('--client-id', help='Azure客户端ID (仅Azure)')
@click.option('--client-secret', help='Azure客户端密钥 (仅Azure)')
@click.option('--use-cli', is_flag=True, help='使用Azure CLI认证 (仅Azure)')
@click.option('--use-msi', is_flag=True, help='使用托管服务标识认证 (仅Azure)')
@click.option('--region', help='指定区域')
@click.option('--output-dir', default='output', help='输出目录路径')
@click.option('--verbose', is_flag=True, help='启用详细日志')
def audit(provider, role_arn, profile, access_key_id, secret_access_key, 
         session_token, external_id, subscription_id, tenant_id, client_id, 
         client_secret, use_cli, use_msi, region, output_dir, verbose):
    """执行云资源审计，收集资产、权限和网络配置数据
    
    支持多种认证方式：
    
    AWS/阿里云/腾讯云:
    1. 使用配置文件（--profile）
    2. 使用访问密钥（--access-key-id 和 --secret-access-key）
    3. 使用临时凭证（需要额外提供 --session-token）
    
    Azure:
    1. 使用Azure CLI认证（--use-cli）
    2. 使用服务主体（--subscription-id, --tenant-id, --client-id, --client-secret）
    3. 使用托管服务标识（--use-msi）
    
    角色切换（仅AWS）：
    - 使用 --role-arn 指定目标角色
    - 如果需要，可以使用 --external-id 提供External ID
    
    注意：对于腾讯云，--access-key-id 对应SecretId，--secret-access-key 对应SecretKey，--session-token 对应Token
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # 确保输出目录存在
        os.makedirs(os.path.join('output_all',output_dir), exist_ok=True)

        logger.info(f"开始 {provider} 资源审计")

        # 准备会话参数
        session_params = {}
        
        # 处理认证方式
        if provider == 'azure':
            # Azure 认证处理
            if subscription_id:
                session_params['subscription_id'] = subscription_id
            else:
                raise click.ClickException("Azure 需要提供 --subscription-id 参数")
            
            if use_cli:
                session_params['use_cli'] = True
                logger.info("使用 Azure CLI 认证")
            elif use_msi:
                session_params['use_msi'] = True
                logger.info("使用托管服务标识认证")
            elif tenant_id and client_id and client_secret:
                session_params.update({
                    'tenant_id': tenant_id,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'use_cli': False
                })
                logger.info("使用服务主体认证")
            else:
                # 默认使用 Azure CLI 认证
                session_params['use_cli'] = True
                logger.info("未指定认证方式，默认使用 Azure CLI 认证")
        elif profile:
            session_params['profile'] = profile
            logger.info(f"使用配置文件 {profile} 创建会话")
        elif access_key_id and secret_access_key:
            if provider == 'aliyun':
                session_params.update({
                    'access_key_id': access_key_id,
                    'access_key_secret': secret_access_key,  # 阿里云使用access_key_secret
                })
            elif provider == 'qcloud':
                session_params.update({
                    'secret_id': access_key_id,  # 腾讯云使用secret_id
                    'secret_key': secret_access_key,  # 腾讯云使用secret_key
                    'token': session_token,  # 腾讯云使用token（可能为None）
                })
            else:
                session_params.update({
                    'access_key_id': access_key_id,
                    'secret_access_key': secret_access_key,
                    'session_token': session_token,  # 可能为None
                })
            logger.info("使用访问密钥创建会话")
            if session_token:
                logger.info("使用临时凭证")

        # 添加区域参数（无论使用哪种认证方式）
        if region:
            # 为不同云提供商映射区域参数
            if provider == 'aliyun':
                session_params['region_id'] = region
            elif provider == 'azure':
                # Azure 不需要在会话创建时指定区域，区域在资源查询时处理
                pass
            elif provider == 'qcloud':
                session_params['region'] = region
            else:
                session_params['region'] = region
            logger.info(f"使用区域: {region}")
        

        # 处理角色切换
        if role_arn:
            session_params.update({
                'role_arn': role_arn,
                'external_id': external_id  # 可能为None
            })
            logger.info(f"将使用角色: {role_arn}")
            if external_id:
                logger.debug(f"使用External ID进行角色切换")

        # 移除所有None值
        session_params = {k: v for k, v in session_params.items() if v is not None}
        
        # 记录最终传递的参数
        logger.info(f"最终传递给create_session的参数: {session_params}")

        # 创建会话
        session = cloud_manager.create_session(provider, **session_params)

        # 获取当前账号ID以确认
        account_id = session.get_account_id()
        logger.info(f"当前操作的账号: {account_id}")

        regions = session.get_enabled_regions()
        logger.info(f"支持的区域: {regions}")

        global_region = cloud_manager.get_global_region(provider)
        if global_region is not None:
            regions.insert(0, "global")
            logger.info(f"支持的区域+全局: {regions}")

        regionIndex = -1
        region_summary = []  # 存储每个区域的统计信息
        
        for regionOne in regions:
            regionIndex += 1
            # 如果是阿里云，区域是字典格式，需要提取RegionId
            if provider == 'aliyun':
                if regionOne == "global":
                    region_id = regionOne
                else:
                    region_id = regionOne.get('RegionId')
                
                if region and region_id != region and region_id != "global":
                    continue
            
                output_dir_region = f"output_all/{output_dir}/{region_id}"
                
                # 为阿里云每个区域创建独立的session
                region_session_params = session_params.copy()
                if region_id == "global":
                    region_session_params['region_id'] = global_region
                else:
                    region_session_params['region_id'] = region_id
                    
                logger.info(f"为区域 {region_id} 创建独立的session")
                region_session = cloud_manager.create_session(provider, **region_session_params)
                current_session = region_session
                
            elif provider == 'azure':
                # Azure 区域是字符串格式 但是不区分区域
                if regionIndex != 0:
                    continue
                region_id = regionOne
                output_dir_region = f"output_all/{output_dir}/{region_id}"

                if regionOne == "global":
                    region_id = global_region
                    current_session = session 
                else:
                    region_id = regionOne
                    current_session = session
            elif provider == 'qcloud':
                # 腾讯云区域是字符串格式
                if region and regionOne != region:
                    continue
                output_dir_region = f"output_all/{output_dir}/{regionOne}"
                region_id = regionOne
                
                # 为腾讯云每个区域创建独立的session
                region_session_params = session_params.copy()
                if regionOne == "global":
                    region_session_params['region'] = global_region
                else:
                    region_session_params['region'] = regionOne
                
                logger.info(f"为区域 {regionOne} 创建独立的session")
                region_session = cloud_manager.create_session(provider, **region_session_params)
                current_session = region_session
            else:
                # AWS等其他provider，区域是字符串格式
                if region and regionOne != region:
                    continue
                output_dir_region = f"output_all/{output_dir}/{regionOne}"
                region_id = regionOne
                
                # 为AWS等其他云提供商每个区域创建独立的session
                region_session_params = session_params.copy()
                if regionOne == "global":
                    region_session_params['region'] = global_region
                else:
                    region_session_params['region'] = regionOne
                
                logger.info(f"为区域 {regionOne} 创建独立的session")
                region_session = cloud_manager.create_session(provider, **region_session_params)
                current_session = region_session

            logger.info(f"使用区域: {regionOne}")
            # 创建审计器并执行审计
            logger.info("开始收集资源信息...")
            auditor = cloud_manager.create_auditor(provider, current_session, output_dir_region)

            # 执行审计
            if regionOne == "global":
                auditor.run_audit_global()
            else:
                auditor.run_audit()

            logger.info(f"审计完成，结果已保存到 {output_dir_region} 目录")

            # 显示结果摘要
            click.echo(f"\n审计结果摘要:")
            click.echo(f"- 云提供商: {provider}")
            click.echo(f"- 账号: {account_id}")
            click.echo(f"- 输出目录: {output_dir_region}")
            click.echo(f"- 资产数据: {output_dir_region}/assets/")

            # 添加区域统计信息
            region_summary.append({
                'region': regionOne,
                'output_dir': output_dir_region
            })

        # 添加汇总统计信息
        click.echo("\n汇总统计信息:")
        for summary in region_summary:
            click.echo(f"- 区域: {summary['region']}")
            click.echo(f"- 输出目录: {summary['output_dir']}")
        merged_output_core(output_dir)

    except Exception as e:
        logger.error(f"审计过程中发生错误: {str(e)}", exc_info=True)
        click.echo(f"错误: {str(e)}", err=True)

@cli.command()
def list_providers():
    """列出支持的云服务提供商"""
    providers = cloud_manager.supported_providers
    click.echo("支持的云服务提供商:")
    for provider in providers:
        click.echo(f"- {provider}")

@cli.command()
@click.option('--output-dir', default='output', help='输出目录路径')
def merged_output(output_dir: str):
    """合并输出目录"""
    merged_output_core(output_dir)



if __name__ == '__main__':
    cli()
