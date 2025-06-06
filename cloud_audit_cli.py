#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Audit CLI - A multi-cloud resource auditing tool
"""
import click
import logging
import os
from cloud_audit.factory import manager as cloud_manager

# 配置日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cloud-audit')


@click.group()
def cli():
    """多云资源审计工具 - 收集云账号资源和权限信息"""
    pass


@cli.command()
@click.option('--provider', type=click.Choice(cloud_manager.supported_providers), required=True,
              help='云服务提供商 (aws, aliyun, gcp)')
@click.option('--role-arn', help='要切换到的IAM角色ARN (仅AWS)')
@click.option('--profile', help='使用的配置文件名称')
@click.option('--access-key-id', help='访问密钥ID')
@click.option('--secret-access-key', help='访问密钥')
@click.option('--session-token', help='会话令牌（使用临时凭证时需要）')
@click.option('--external-id', help='角色切换时的External ID（如果需要）')
@click.option('--region', help='指定区域')
@click.option('--output-dir', default='output', help='输出目录路径')
@click.option('--verbose', is_flag=True, help='启用详细日志')
def audit(provider, role_arn, profile, access_key_id, secret_access_key, 
         session_token, external_id, region, output_dir, verbose):
    """执行云资源审计，收集资产、权限和网络配置数据
    
    支持多种认证方式：
    1. 使用配置文件（--profile）
    2. 使用访问密钥（--access-key-id 和 --secret-access-key）
    3. 使用临时凭证（需要额外提供 --session-token）
    
    角色切换：
    - 使用 --role-arn 指定目标角色
    - 如果需要，可以使用 --external-id 提供External ID
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"开始 {provider} 资源审计")

        # 准备会话参数
        session_params = {}
        
        # 处理认证方式
        if profile:
            session_params['profile'] = profile
            logger.info(f"使用配置文件 {profile} 创建会话")
        elif access_key_id and secret_access_key:
            if provider == 'aliyun':
                session_params.update({
                    'access_key_id': access_key_id,
                    'access_key_secret': secret_access_key,  # 阿里云使用access_key_secret
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

        for regionOne in regions:
            # 如果是阿里云，区域是字典格式，需要提取RegionId
            if provider == 'aliyun' and isinstance(regionOne, dict):
                region_id = regionOne.get('RegionId')
                if region and region_id != region:
                    continue
                output_dir_region = f"{output_dir}/{region_id}"
            else:
                # AWS等其他provider，区域是字符串格式
                if region and regionOne != region:
                    continue
                output_dir_region = f"{output_dir}/{regionOne}"
                region_id = regionOne

            logger.info(f"使用区域: {regionOne}")
            # 创建审计器并执行审计
            logger.info("开始收集资源信息...")
            auditor = cloud_manager.create_auditor(provider, session, output_dir_region)

            # 执行审计
            auditor.run_audit()

            logger.info(f"审计完成，结果已保存到 {output_dir_region} 目录")

            # 显示结果摘要
            click.echo(f"\n审计结果摘要:")
            click.echo(f"- 云提供商: {provider}")
            click.echo(f"- 账号: {account_id}")
            click.echo(f"- 输出目录: {output_dir_region}")
            click.echo(f"- 资产数据: {output_dir_region}/assets/")
            click.echo(f"- 权限数据: {output_dir_region}/permissions/")
            click.echo(f"- 网络数据: {output_dir_region}/network/")

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


if __name__ == '__main__':
    cli()
