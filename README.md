# Flowith2API - Deno版本

[![Deno](https://img.shields.io/badge/deno-1.x-blue.svg)](https://deno.land/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

一个基于Deno的Flowith API代理服务，提供OpenAI兼容的API接口，支持多Token负载均衡、会话管理、MCP工具集成等企业级特性。

## ✨ 主要特性

- 🚀 **OpenAI兼容API** - 完全兼容OpenAI的接口格式
- 🔄 **Token负载均衡** - 支持多Token轮询，自动故障切换
- 💾 **多种存储方案** - 支持Deno KV、SQLite、内存三种存储方式
- 🧠 **长上下文支持** - 自动会话管理和上下文保持
- 🛠️ **MCP工具集成** - 内置多种工具（搜索、图像生成、代码执行等）
- 🖥️ **CLI模式** - 支持文件系统操作和命令执行
- 📊 **统计与监控** - 实时请求统计和性能监控
- 🔐 **灵活的鉴权** - 支持多API Key管理
- 🎯 **智能重试** - 可配置的重试策略和超时控制
- 🤖 **Claude API兼容** - 同时支持Claude API格式

## 📦 快速开始

### 前置要求

- Deno 1.x 或更高版本
- Flowith API Token

### 方式1：一键部署到Deno Deploy

[![Deploy on Deno Deploy](https://deno.com/deno-deploy-button.svg)](https://dash.deno.com/new?url=https://raw.githubusercontent.com/XxxXTeam/flowith2api_deno/main/main.ts)

1. 点击上方按钮
2. 在Deno Deploy中设置环境变量（见[环境变量配置](#环境变量配置)）
3. 部署完成！

### 方式2：本地运行

```bash
# 1. 克隆仓库
git clone https://github.com/XxxXTeam/flowith2api_deno.git
cd flowith2api_deno

# 2. 复制环境变量配置文件
cp env.example .env

# 3. 编辑 .env 文件，配置你的Token
# 至少需要设置 FLOWITH_AUTH_TOKENS 和 API_KEYS

# 4. 运行服务
deno run --allow-net --allow-env --allow-read --allow-write main.ts
```

服务将在 `http://localhost:8787` 启动。

### 方式3：Docker部署

```bash
# 使用官方Deno镜像
docker run -d \
  --name flowith2api \
  -p 8787:8787 \
  -v $(pwd)/.env:/app/.env \
  -v $(pwd)/data:/app/data \
  denoland/deno:latest \
  run --allow-net --allow-env --allow-read --allow-write \
  https://raw.githubusercontent.com/XxxXTeam/flowith2api_deno/main/main.ts
```

### 方式4：使用systemd守护进程（Linux）

创建服务文件 `/etc/systemd/system/flowith2api.service`:

```ini
[Unit]
Description=Flowith2API Deno Service
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/flowith2api_deno
ExecStart=/usr/bin/deno run --allow-net --allow-env --allow-read --allow-write main.ts
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启动服务:

```bash
sudo systemctl daemon-reload
sudo systemctl enable flowith2api
sudo systemctl start flowith2api
sudo systemctl status flowith2api
```

## ⚙️ 环境变量配置

### 基础配置

| 变量名 | 说明 | 默认值 | 必需 |
|--------|------|--------|------|
| `PORT` | 服务监听端口 | `8787` | 否 |
| `LOG_LEVEL` | 日志级别 (debug/info/warn/error) | `info` | 否 |
| `FLOWITH_AUTH_TOKENS` | Flowith认证Token（逗号分隔） | - | 是 |
| `API_KEYS` | API访问密钥（逗号分隔） | - | 是 |
| `ADMIN_KEY` | 管理员密钥 | 第一个API_KEY | 否 |

### 上游配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `FLOWITH_BASE` | 自定义上游地址 | - |
| `FLOWITH_REGION` | 上游区域 | - |
| `PROXY_URL` | HTTP代理地址 | - |

### 存储配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `STORAGE_TYPE` | 存储类型 (kv/sqlite/memory) | `kv` |
| `DENO_KV_PATH` | Deno KV数据库路径 | - |
| `SQLITE_PATH` | SQLite数据库路径 | `./data/flowith.db` |
| `DATA_PATH` | 数据目录（SQLITE_PATH别名） | `./data/flowith.db` |

### 超时配置

| 变量名 | 说明 | 默认值（毫秒） |
|--------|------|---------------|
| `UPSTREAM_TIMEOUT_MS` | 上游请求头超时 | `25000` |
| `UPSTREAM_BODY_TIMEOUT_MS` | 上游响应体超时 | `30000` |
| `STREAM_IDLE_TIMEOUT_MS` | 流式空闲超时 | `15000` |
| `STREAM_TOTAL_TIMEOUT_MS` | 流式总超时 | `180000` |

### 重试配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `UPSTREAM_RETRY_MAX` | 最大重试次数 | `3` |
| `UPSTREAM_RETRY_BACKOFF_MS` | 重试退避基础时间（毫秒） | `200` |
| `SSE_RETRY_ON_EMPTY` | SSE空返回时重试 | `true` |
| `SSE_MIN_CONTENT_LENGTH` | SSE最小内容长度 | `10` |
| `NO_RETRY_ON_TIMEOUT` | 超时时不重试 | `true` |

### 长上下文配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ENABLE_LONG_CONTEXT` | 启用长上下文支持 | `true` |
| `MAX_CONTEXT_MESSAGES` | 最大保存消息数 | `20` |
| `CONTEXT_TTL_SECONDS` | 会话过期时间（秒） | `3600` |

### 功能开关

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ENABLE_THINKING_INJECTION` | 启用思考提示注入 | `true` |
| `THINKING_PROMPT` | 思考提示内容 | `Please think step by step...` |
| `ENABLE_MCP` | 启用MCP工具 | `true` |
| `MCP_TOOLS` | 可用工具列表（逗号分隔） | - |
| `ENABLE_CLI_MODE` | 启用CLI模式 | `false` |
| `ENABLE_CLAUDE_API` | 启用Claude API兼容 | `true` |
| `ENABLE_THINKING_TAGS` | 启用思考标签 | `true` |
| `ENABLE_STREAM_OPTIMIZATION` | 启用流优化 | `true` |
| `SERVER_ONLY` | 仅服务端模式 | `false` |

### 系统提示词配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SYSTEM_PROMPT` | 自定义系统提示词 | - |
| `ENABLE_SYSTEM_PROMPT_OVERRIDE` | 覆盖原有系统提示词 | `false` |
| `MCP_PROMPT` | MCP工具提示词 | `You have access to...` |
| `CLI_PROMPT` | CLI模式提示词 | `You are an AI assistant...` |

### 完整配置示例

参考 [`env.example`](env.example) 文件获取完整配置示例。

## 📡 API端点

### 聊天完成接口

#### OpenAI格式

```bash
POST /v1/chat/completions
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "model": "flowith",
  "messages": [
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false,
  "session_id": "optional-session-id",
  "auto_session": true
}
```

#### Claude格式

```bash
POST /v1/messages
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY
anthropic-version: 2023-06-01

{
  "model": "claude-3-5-sonnet",
  "messages": [
    {"role": "user", "content": "Hello!"}
  ],
  "max_tokens": 1024
}
```

### 模型列表

```bash
GET /v1/models
Authorization: Bearer YOUR_API_KEY
```

### 管理接口

所有管理接口需要使用 `ADMIN_KEY` 鉴权。

#### 统计信息

```bash
GET /v1/admin/stats
Authorization: Bearer YOUR_ADMIN_KEY
```

#### Token管理

```bash
# 列出所有Token
GET /v1/admin/tokens
Authorization: Bearer YOUR_ADMIN_KEY

# 添加Token
POST /v1/admin/tokens
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "token": "new-flowith-token"
}

# 删除Token
DELETE /v1/admin/tokens
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "token": "token-to-remove"
}

# 重置Token索引
PUT /v1/admin/tokens
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "index": 0
}

# 清空所有Token
POST /v1/admin/tokens/clear
Authorization: Bearer YOUR_ADMIN_KEY
```

#### 配置管理

```bash
# 查看配置
GET /v1/admin/config
Authorization: Bearer YOUR_ADMIN_KEY

# 更新配置
PATCH /v1/admin/config
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "logLevel": "debug",
  "retryMax": 5,
  "enableMCP": true
}
```

#### 会话管理

```bash
# 查看会话
GET /v1/admin/sessions?session_id=SESSION_ID
Authorization: Bearer YOUR_ADMIN_KEY

# 删除会话
DELETE /v1/admin/sessions?session_id=SESSION_ID
Authorization: Bearer YOUR_ADMIN_KEY
```

#### 工具测试

```bash
POST /v1/admin/tools/execute
Authorization: Bearer YOUR_ADMIN_KEY
Content-Type: application/json

{
  "tool": "file_read",
  "arguments": {
    "path": "./test.txt"
  }
}
```

#### Token导出

```bash
# JSON格式导出
GET /v1/admin/tokens/export?format=json
Authorization: Bearer YOUR_ADMIN_KEY

# 文本格式导出
GET /v1/admin/tokens/export?format=text
Authorization: Bearer YOUR_ADMIN_KEY

# 环境变量格式导出
GET /v1/admin/tokens/export?format=env
Authorization: Bearer YOUR_ADMIN_KEY
```

## 🏗️ 系统架构与模块

### 核心模块

#### 1. 存储抽象层 (Storage Layer)

提供统一的存储接口，支持三种存储方案：

- **Deno KV** - Deno原生KV存储，适合部署到Deno Deploy
- **SQLite** - 本地SQLite数据库，适合自托管场景
- **Memory** - 内存存储，适合临时测试

```typescript
interface StorageAdapter {
  get<T>(key: string[]): Promise<T | null>;
  set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void>;
  delete(key: string[]): Promise<void>;
  close(): Promise<void>;
}
```

#### 2. 配置管理系统 (Configuration Manager)

集中管理所有配置项，支持运行时动态更新和持久化。

#### 3. Token管理器 (Token Manager)

- 轮询策略的Token选择
- 自动故障检测和移除
- Token使用统计
- 支持Token分片存储（突破KV大小限制）

#### 4. 会话管理器 (Session Manager)

- 自动会话ID生成
- 上下文历史保存
- 知识库列表复用
- 会话过期清理

#### 5. MCP工具引擎 (MCP Tool Engine)

内置15+种工具：

**通用工具：**
- `web_search` - 网络搜索
- `image_gen` - 图像生成
- `code_interpreter` - 代码执行

**CLI工具（需启用CLI模式）：**
- `file_read/write/edit/delete/move` - 文件操作
- `file_list/search` - 文件浏览
- `directory_create/delete` - 目录管理
- `bash_execute` - 命令执行
- `git_status/diff` - Git操作
- `environment_info` - 环境信息
- `search_files` - 文本搜索

#### 6. 请求处理流程

```
客户端请求
    ↓
鉴权验证
    ↓
消息规范化
    ↓
会话上下文加载
    ↓
系统提示词注入
    ↓
MCP工具准备
    ↓
Token选择（负载均衡）
    ↓
上游请求（带重试）
    ↓
工具调用检测与执行
    ↓
响应格式转换
    ↓
会话保存
    ↓
返回客户端
```

## 🔧 调试与故障排除

### 启用调试日志

设置环境变量：

```bash
export LOG_LEVEL=debug
```

或在运行时通过管理API更新：

```bash
curl -X PATCH http://localhost:8787/v1/admin/config \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"logLevel": "debug"}'
```

### 常见问题

#### 1. Token相关错误

**问题：** `No tokens configured` 或 `No tokens available`

**解决：**
```bash
# 检查Token配置
curl http://localhost:8787/v1/admin/tokens \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"

# 添加新Token
curl -X POST http://localhost:8787/v1/admin/tokens \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token": "your-flowith-token"}'
```

#### 2. 存储初始化失败

**问题：** `Storage initialization failed`

**解决：**
```bash
# 方案1：切换到SQLite存储
export STORAGE_TYPE=sqlite
export SQLITE_PATH=./data/flowith.db
mkdir -p ./data

# 方案2：切换到内存存储（临时）
export STORAGE_TYPE=memory
```

#### 3. 上游超时

**问题：** `upstream timeout` 或 `REQUEST_TIMED_OUT`

**解决：**
```bash
# 增加超时时间
export UPSTREAM_TIMEOUT_MS=60000
export UPSTREAM_BODY_TIMEOUT_MS=90000
export STREAM_TOTAL_TIMEOUT_MS=300000
```

#### 4. 流式响应问题

**问题：** 流式响应卡住或中断

**解决：**
```bash
# 调整流式超时配置
export STREAM_IDLE_TIMEOUT_MS=30000
export STREAM_TOTAL_TIMEOUT_MS=300000

# 启用空返回重试
export SSE_RETRY_ON_EMPTY=true
```

#### 5. 会话上下文丢失

**问题：** 上下文无法保持

**解决：**
```bash
# 确保启用长上下文
export ENABLE_LONG_CONTEXT=true

# 增加上下文保存数量和TTL
export MAX_CONTEXT_MESSAGES=50
export CONTEXT_TTL_SECONDS=7200

# 使用持久化存储（非memory）
export STORAGE_TYPE=sqlite
```

### 日志分析

日志采用结构化JSON格式，可以使用jq进行过滤：

```bash
# 查看所有错误
deno run main.ts 2>&1 | jq 'select(.level=="error")'

# 查看特定请求ID的日志
deno run main.ts 2>&1 | jq 'select(.请求ID=="xxx")'

# 统计请求数
deno run main.ts 2>&1 | jq 'select(.事件=="聊天请求")' | wc -l
```

### 性能监控

通过统计API监控服务状态：

```bash
# 查看实时统计
watch -n 5 'curl -s http://localhost:8787/v1/admin/stats \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" | jq'
```

### 健康检查

```bash
# 基础健康检查
curl -I http://localhost:8787/v1/models

# 完整功能检查
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [{"role": "user", "content": "test"}],
    "stream": false
  }'
```

## 📚 使用示例

### Python客户端

```python
from openai import OpenAI

client = OpenAI(
    api_key="YOUR_API_KEY",
    base_url="http://localhost:8787/v1"
)

# 简单对话
response = client.chat.completions.create(
    model="flowith",
    messages=[
        {"role": "user", "content": "你好！"}
    ]
)
print(response.choices[0].message.content)

# 流式对话
stream = client.chat.completions.create(
    model="flowith",
    messages=[
        {"role": "user", "content": "讲个故事"}
    ],
    stream=True
)

for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="")
```

### curl示例

```bash
# 非流式请求
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "你好！"}
    ]
  }' | jq

# 流式请求
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "讲个故事"}
    ],
    "stream": true
  }'

# 使用会话ID保持上下文
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "我喜欢Python"}
    ],
    "session_id": "my-session-123"
  }'

# 继续上一个会话
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "我刚才说我喜欢什么？"}
    ],
    "session_id": "my-session-123"
  }'
```

### JavaScript客户端

```javascript
// Node.js
const OpenAI = require('openai');

const client = new OpenAI({
  apiKey: 'YOUR_API_KEY',
  baseURL: 'http://localhost:8787/v1'
});

async function chat() {
  const response = await client.chat.completions.create({
    model: 'flowith',
    messages: [
      { role: 'user', content: '你好！' }
    ]
  });
  
  console.log(response.choices[0].message.content);
}

chat();
```

### 使用MCP工具

```bash
# 启用MCP工具
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "帮我搜索一下最新的AI新闻"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "web_search",
          "description": "Search the web",
          "parameters": {
            "type": "object",
            "properties": {
              "query": {"type": "string"}
            },
            "required": ["query"]
          }
        }
      }
    ]
  }'
```

### CLI模式示例

```bash
# 启用CLI模式
export ENABLE_CLI_MODE=true

# 文件操作示例
curl -X POST http://localhost:8787/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "flowith",
    "messages": [
      {"role": "user", "content": "读取 README.md 文件的前10行"}
    ]
  }'
```

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 许可证

[MIT License](LICENSE)

## 🔗 相关链接

- [Flowith 官网](https://flowith.io/)
- [Deno 官方文档](https://deno.land/manual)
- [Deno Deploy](https://deno.com/deploy)
- [OpenAI API 文档](https://platform.openai.com/docs/api-reference)

## 📮 联系方式

- Issue: [GitHub Issues](https://github.com/XxxXTeam/flowith2api_deno/issues)

---

**注意事项：**
- 本项目仅供学习和研究使用
- 请确保遵守Flowith的服务条款
- 生产环境部署时请注意安全配置（使用强密码、启用HTTPS等）