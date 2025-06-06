# 多云资源审计工具

这个工具用于全面收集各个云平台的资源信息、权限配置和网络设置。目前支持AWS和阿里云，并计划支持GCP。

## 功能特点

### 多云支持
- AWS（已实现）
- 阿里云（已实现）

### 资源收集范围

#### AWS资源
- **计算资源**：EC2、Lambda、ECS、EKS等
- **存储资源**：S3、EBS、EFS、FSx等
- **数据库资源**：RDS、DynamoDB、ElastiCache、Redshift等
- **网络资源**：VPC、子网、安全组、ACL、路由表等
- **安全资源**：IAM用户、角色、策略、KMS密钥等
- **应用服务**：SNS、SQS、SES等
- **分析服务**：Athena、EMR、Kinesis等
- **监控服务**：CloudWatch、CloudTrail等

#### 阿里云资源
- **计算资源**：ECS实例、安全组等
- **存储资源**：OSS对象存储、磁盘等
- **数据库资源**：RDS、MongoDB、Redis、PolarDB等
- **网络资源**：VPC、交换机、路由表、网络ACL、NAT网关等
- **安全资源**：RAM用户、角色、策略等
- **监控和安全服务**：云安全中心、WAF、DDoS高防、云监控等
- **传输网关**：云企业网、VPN网关、高速通道等

## 安装

1. 克隆仓库：
```bash
git clone <repository-url>
cd cloud-audit
```

2. 创建并激活虚拟环境：
```bash
# 创建虚拟环境
python -m venv venv

# 在Linux/Mac上激活虚拟环境
source venv/bin/activate
# 或者使用提供的激活脚本
./activate.sh

# 在Windows上激活虚拟环境
venv\Scripts\activate
```

3. 安装依赖：
```bash
# 安装所有依赖
pip install -r requirements.txt
```

### SSL证书问题解决方案

如果在安装过程中遇到SSL证书验证错误，可以使用以下方法：

```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```


## 使用方法


### 基本用法

#### 1. 列出支持的云服务提供商：
```bash
python cloud_audit_cli.py list-providers
```

#### 2. 执行审计：
```bash

# 执行 aws 审计
python cloud_audit_cli.py audit \
--provider aws \
--access-key-id xxxx \
--secret-access-key xxxxx \
--output-dir output_xxx

# 执行aliyun审计
python cloud_audit_cli.py audit \
--provider aliyun \
--access-key-id xxxx \
--secret-access-key xxxxx \
--output-dir output_xxx

# 推荐使用 profile (可以配合角色切换)
python cloud_audit_cli.py audit \
--provider aliyun/aws \
--profile xxx \
--role-arn acs:ram::xxxx:role/xxx \
--output-dir output_xxx
```

##### 参数说明

`python cloud_audit_cli.py audit` 命令支持以下参数：

###### 必需参数
- `--provider` - 云服务提供商，支持以下选项：
  - `aws` - Amazon Web Services
  - `aliyun` - 阿里云

###### 认证参数
- `--profile` - 使用的配置文件名称
  - AWS: 使用 AWS CLI 配置文件 (`~/.aws/config` 和 `~/.aws/credentials`)
  - 阿里云: 使用阿里云 CLI 配置文件 (`~/.aliyun/config.json`)

- `--access-key-id` - 访问密钥ID
  - 需要与 `--secret-access-key` 配合使用

- `--secret-access-key` - 访问密钥
  - AWS: Secret Access Key
  - 阿里云: Access Key Secret

###### 角色切换参数
- `--role-arn` - 要切换到的IAM/RAM角色ARN
  - 格式：`arn:aws:iam::account-id:role/role-name`

###### 其他参数
- `--region` - 可以指定区域，但是指定区域会丢失其他区域数据，可能导致数据不全
  - AWS: 如 `us-east-1`, `us-west-2`, `ap-northeast-1` 等
  - 阿里云: 如 `cn-hangzhou`, `cn-beijing`, `cn-shanghai` 等
  - 如果不指定，将审计所有可用区域

- `--output-dir` - 输出目录路径（默认：`output`）
  - 审计结果将保存在此目录下

## 输出结构

审计结果将保存在指定的输出目录（默认为`output`）中，按以下结构组织：

```
output/
├── assets/
│   └── all_assets.json    # 所有资源清单
```

## 注意事项

1. 大型云账号可能会产生大量数据，请确保有足够的磁盘空间
2. 审计过程可能需要几分钟到几十分钟不等，取决于账号中的资源数量
3. 某些API调用可能会因权限不足而失败，工具会跳过这些错误并继续收集其他数据
4. 如果使用角色切换，角色切换时，确保源账户有权限切换到目标角色，且目标角色的信任策略允许源账户切换
5. 审计过程中，由于频繁拉取云资源列表和基本信息，可能会产生云安全报警

## 故障排除

### 角色切换失败
- 检查源账户是否有`sts:AssumeRole`权限
- 确认目标角色的信任策略是否允许源账户切换
- 如果角色需要External ID，确保提供了正确的值
- 检查角色ARN是否正确

### 审计过程中出现权限错误
- 确保使用的用户或角色有足够的权限
- 对于跨账户审计，确保目标角色有足够的权限

## 许可证

MIT License