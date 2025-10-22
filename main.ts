import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { DB } from "https://deno.land/x/sqlite/mod.ts";

// ============ 存储抽象层 ============
interface StorageAdapter {
  get<T>(key: string[]): Promise<T | null>;
  set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void>;
  delete(key: string[]): Promise<void>;
  close(): Promise<void>;
}

// SQLite 存储适配器
class SQLiteAdapter implements StorageAdapter {
  private db: DB;
  private cleanupTimer?: number;
  private isClosed = false;

  constructor(path: string) {
    try {
    this.db = new DB(path);
    this.db.execute(`
    CREATE TABLE IF NOT EXISTS kv_store (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
        expire_at INTEGER,
        created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
        updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
    )
    `);
    this.db.execute(`CREATE INDEX IF NOT EXISTS idx_expire ON kv_store(expire_at)`);
      this.db.execute(`CREATE INDEX IF NOT EXISTS idx_created ON kv_store(created_at)`);
      
    // 定期清理过期数据
      this.cleanupTimer = setInterval(() => this.cleanup(), 60000) as unknown as number;
      
      console.log(`[SQLite] Adapter initialized at ${path}`);
    } catch (e) {
      console.error("[SQLite] Initialization error:", e);
      throw e;
    }
  }

  private cleanup() {
    if (this.isClosed) return;
    
    try {
      const now = Date.now();
      const result = this.db.query("DELETE FROM kv_store WHERE expire_at IS NOT NULL AND expire_at < ?", [now]);
      if (result && result.length > 0) {
        console.log(`[SQLite] Cleaned up expired entries`);
      }
    } catch (e) {
      console.error("[SQLite] Cleanup error:", e);
    }
  }

  async get<T>(key: string[]): Promise<T | null> {
    if (this.isClosed) {
      console.warn("[SQLite] Attempted to get from closed database");
      return null;
    }
    
    try {
    const keyStr = JSON.stringify(key);
    const now = Date.now();
    const rows = this.db.query("SELECT value FROM kv_store WHERE key = ? AND (expire_at IS NULL OR expire_at > ?)", [keyStr, now]);

    if (rows.length === 0) return null;

    try {
      return JSON.parse(rows[0][0] as string) as T;
      } catch (e) {
        console.error("[SQLite] JSON parse error:", e);
        return null;
      }
    } catch (e) {
      console.error("[SQLite] Get error:", e);
      return null;
    }
  }

  async set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void> {
    if (this.isClosed) {
      console.warn("[SQLite] Attempted to set on closed database");
      return;
    }
    
    try {
    const keyStr = JSON.stringify(key);
    const valueStr = JSON.stringify(value);
    const expireAt = options?.expireIn ? Date.now() + options.expireIn : null;
      const now = Date.now();

    this.db.query(
        "INSERT OR REPLACE INTO kv_store (key, value, expire_at, updated_at) VALUES (?, ?, ?, ?)",
                    [keyStr, valueStr, expireAt, now]
    );
    } catch (e) {
      console.error("[SQLite] Set error:", e);
      throw e;
    }
  }

  async delete(key: string[]): Promise<void> {
    if (this.isClosed) {
      console.warn("[SQLite] Attempted to delete from closed database");
      return;
    }
    
    try {
    const keyStr = JSON.stringify(key);
    this.db.query("DELETE FROM kv_store WHERE key = ?", [keyStr]);
    } catch (e) {
      console.error("[SQLite] Delete error:", e);
      throw e;
    }
  }

  async close(): Promise<void> {
    if (this.isClosed) return;
    
    this.isClosed = true;
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    
    try {
    this.db.close();
      console.log("[SQLite] Database closed");
    } catch (e) {
      console.error("[SQLite] Close error:", e);
    }
  }
}

// Deno KV 存储适配器
class DenoKVAdapter implements StorageAdapter {
  constructor(private kv: Deno.Kv) {}

  async get<T>(key: string[]): Promise<T | null> {
    const result = await this.kv.get<T>(key);
    return result.value;
  }

  async set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void> {
    await this.kv.set(key, value, options);
  }

  async delete(key: string[]): Promise<void> {
    await this.kv.delete(key);
  }

  async close(): Promise<void> {
    this.kv.close();
  }
}

// 内存存储适配器
class MemoryAdapter implements StorageAdapter {
  private store = new Map<string, { value: any; expireAt?: number }>();

  constructor() {
    setInterval(() => this.cleanup(), 60000);
  }

  private cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.expireAt && entry.expireAt < now) {
        this.store.delete(key);
      }
    }
  }

  async get<T>(key: string[]): Promise<T | null> {
    const keyStr = JSON.stringify(key);
    const entry = this.store.get(keyStr);

    if (!entry) return null;
    if (entry.expireAt && entry.expireAt < Date.now()) {
      this.store.delete(keyStr);
      return null;
    }

    return entry.value as T;
  }

  async set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void> {
    const keyStr = JSON.stringify(key);
    const expireAt = options?.expireIn ? Date.now() + options.expireIn : undefined;
    this.store.set(keyStr, { value, expireAt });
  }

  async delete(key: string[]): Promise<void> {
    const keyStr = JSON.stringify(key);
    this.store.delete(keyStr);
  }

  async close(): Promise<void> {
    this.store.clear();
  }
}

// ============ 环境变量加载（支持非Deno环境）============
function getEnv(key: string, defaultValue: string = ""): string {
  try {
    // 优先使用 Deno.env
    return Deno.env.get(key) ?? defaultValue;
  } catch {
    // 兜底：尝试使用 globalThis 访问 process.env (Node.js环境)
    try {
      const proc = (globalThis as any).process;
      if (proc && proc.env && proc.env[key]) {
        return proc.env[key];
      }
    } catch {
      // 忽略错误
    }
    return defaultValue;
  }
}

// ============ 存储初始化 ============
const STORAGE_TYPE = getEnv("STORAGE_TYPE", "kv").toLowerCase();
let storage: StorageAdapter | null = null;
let kv: Deno.Kv | null = null; // 保留向后兼容

async function initStorage(): Promise<void> {
  const kvPath = getEnv("DENO_KV_PATH");
  const sqlitePath = getEnv("SQLITE_PATH") || getEnv("DATA_PATH") || "./data/flowith.db";

  try {
    if (STORAGE_TYPE === "sqlite") {
      console.log(`[Storage] Initializing SQLite at ${sqlitePath}...`);
      storage = new SQLiteAdapter(sqlitePath);
      console.log(`[Storage] ✓ SQLite initialized successfully`);
    } else if (STORAGE_TYPE === "memory") {
      console.log("[Storage] Initializing memory storage...");
      storage = new MemoryAdapter();
      console.log("[Storage] ✓ Memory storage initialized successfully");
    } else {
      // 默认使用 Deno KV
      let denoKv: Deno.Kv | null = null;
      
      if (kvPath) {
        // 尝试使用自定义路径
        try {
          console.log(`[Storage] Attempting Deno KV with custom path: ${kvPath}...`);
          denoKv = await Deno.openKv(kvPath);
          console.log(`[Storage] ✓ Deno KV initialized with custom path`);
        } catch (kvPathErr) {
          console.warn(`[Storage] Custom KV path failed: ${kvPathErr}`);
          console.log("[Storage] Trying default Deno KV (no path)...");
          // 降级到默认KV
          try {
            denoKv = await Deno.openKv();
            console.log(`[Storage] ✓ Deno KV initialized (default)`);
          } catch (defaultKvErr) {
            console.warn(`[Storage] Default KV also failed: ${defaultKvErr}`);
            throw new Error("Deno KV not available");
          }
        }
      } else {
        // 直接使用默认KV
        console.log("[Storage] Initializing Deno KV (default)...");
        denoKv = await Deno.openKv();
        console.log(`[Storage] ✓ Deno KV initialized successfully`);
      }
      
      if (denoKv) {
        kv = denoKv; // 保留向后兼容
        storage = new DenoKVAdapter(denoKv);
      } else {
        throw new Error("Failed to initialize Deno KV");
      }
    }
    
    // 测试存储是否可用
    if (storage) {
      await storage.set(["_health_check"], { ok: true, timestamp: Date.now() });
      const healthCheck = await storage.get(["_health_check"]);
      if (!healthCheck) {
        throw new Error("Storage health check failed");
      }
      await storage.delete(["_health_check"]);
      console.log("[Storage] Health check passed");
    }
    
  } catch (e) {
    console.error("[Storage] Initialization failed:", e);
    
    // 尝试降级策略
    const fallbackStrategies = [
      {
        name: "SQLite",
        init: async () => {
          console.log(`[Storage] Trying SQLite fallback at ${sqlitePath}...`);
          storage = new SQLiteAdapter(sqlitePath);
        }
      },
      {
        name: "Memory",
        init: async () => {
          console.log("[Storage] Trying memory storage fallback...");
          storage = new MemoryAdapter();
        }
      }
    ];
    
    let fallbackSuccess = false;
    
    for (const strategy of fallbackStrategies) {
      try {
        await strategy.init();
        console.log(`[Storage] ✓ Fallback to ${strategy.name} storage successful`);
        fallbackSuccess = true;
        break;
      } catch (fallbackErr) {
        console.warn(`[Storage] ${strategy.name} fallback failed:`, fallbackErr);
      }
    }
    
    if (!fallbackSuccess) {
      console.error("[Storage] All fallback strategies failed");
      console.error("[Storage] Running without persistent storage");
      storage = null;
    }
  }
}

await initStorage();

// ============ 配置管理系统 ============
interface AppConfig {
  // Token配置
  tokens: string[];
  apiKeys: string[];
  adminKey: string;
  // 服务配置
  port: number;
  logLevel: string;
  // 上游配置
  flowithBase: string;
  flowithRegion: string;
  origin: string;
  // 代理配置
  proxyUrl?: string;
  // 超时配置
  headerTimeoutMs: number;
  bodyTimeoutMs: number;
  streamIdleTimeoutMs: number;
  streamTotalTimeoutMs: number;
  // 重试配置
  retryMax: number;
  retryBackoffBaseMs: number;
  sseRetryOnEmpty: boolean;
  sseMinContentLength: number;
  retryOnStatus: number[];
  noRetryOnTimeout: boolean;
  // 长上下文配置
  enableLongContext: boolean;
  maxContextMessages: number;
  contextTTLSeconds: number;
  // 思考注入配置
  enableThinkingInjection: boolean;
  thinkingPrompt: string;
  // 系统提示词配置
  systemPrompt?: string;
  enableSystemPromptOverride: boolean;
  // MCP配置
  enableMCP: boolean;
  mcpTools: string[];
  mcpPrompt: string;
  // CLI模式配置
  enableCLIMode: boolean;
  cliPrompt: string;
  // 存储配置
  storageType: "kv" | "sqlite" | "memory";
  sqlitePath?: string;
  // 仅服务端模式
  serverOnly: boolean;
  // Claude API 兼容
  enableClaudeAPI: boolean;
  // 思考功能增强
  enableThinkingTags: boolean;
  thinkingTagFormat: "xml" | "markdown" | "custom";
  thinkingStartTag: string;
  thinkingEndTag: string;
  // 性能优化
  enableStreamOptimization: boolean;
}

// 从环境变量加载配置
function loadConfigFromEnv(): AppConfig {
  const flowithBase = getEnv("FLOWITH_BASE").trim();
  const flowithRegion = getEnv("FLOWITH_REGION").trim();
  const origin = flowithBase
  ? flowithBase.replace(/\/+$/, "")
  : (flowithRegion ? `https://${flowithRegion}.edge.flowith.net` : `https://edge.flowith.net`);

  const storageTypeEnv = getEnv("STORAGE_TYPE", "kv").toLowerCase();
  const storageType = (storageTypeEnv === "sqlite" || storageTypeEnv === "memory") ? storageTypeEnv : "kv";

  return {
    // tokens 不从这里加载，而是通过 syncTokensFromEnv() 统一管理
    tokens: [],
    apiKeys: getEnv("API_KEYS").split(",").map(s => s.trim()).filter(Boolean),
    adminKey: getEnv("ADMIN_KEY") || (getEnv("API_KEYS").split(",")[0]?.trim() ?? ""),
    port: Number(getEnv("PORT", "8787")),
    logLevel: getEnv("LOG_LEVEL", "info").toLowerCase(),
    flowithBase,
    flowithRegion,
    origin,
    proxyUrl: getEnv("PROXY_URL") || undefined,
    headerTimeoutMs: Math.max(1000, Number(getEnv("UPSTREAM_TIMEOUT_MS", "25000"))),
    bodyTimeoutMs: Math.max(2000, Number(getEnv("UPSTREAM_BODY_TIMEOUT_MS", "30000"))),
    streamIdleTimeoutMs: Math.max(2000, Number(getEnv("STREAM_IDLE_TIMEOUT_MS", "15000"))),
    streamTotalTimeoutMs: Math.max(5000, Number(getEnv("STREAM_TOTAL_TIMEOUT_MS", "180000"))),
    retryMax: Math.max(0, Number(getEnv("UPSTREAM_RETRY_MAX", "3"))),
    retryBackoffBaseMs: Math.max(0, Number(getEnv("UPSTREAM_RETRY_BACKOFF_MS", "200"))),
    sseRetryOnEmpty: getEnv("SSE_RETRY_ON_EMPTY", "true").toLowerCase() === "true",
    sseMinContentLength: Math.max(0, Number(getEnv("SSE_MIN_CONTENT_LENGTH", "10"))),
    retryOnStatus: [401, 403, 408, 402, 409, 425, 429, 500, 502, 503, 504],
    noRetryOnTimeout: getEnv("NO_RETRY_ON_TIMEOUT", "true").toLowerCase() === "true",
    enableLongContext: getEnv("ENABLE_LONG_CONTEXT", "true").toLowerCase() === "true",
    maxContextMessages: Math.max(1, Number(getEnv("MAX_CONTEXT_MESSAGES", "20"))),
    contextTTLSeconds: Math.max(60, Number(getEnv("CONTEXT_TTL_SECONDS", "3600"))),
    enableThinkingInjection: getEnv("ENABLE_THINKING_INJECTION", "true").toLowerCase() === "true",
    thinkingPrompt: getEnv("THINKING_PROMPT", "Please think step by step before answering."),
    systemPrompt: getEnv("SYSTEM_PROMPT") || undefined,
    enableSystemPromptOverride: getEnv("ENABLE_SYSTEM_PROMPT_OVERRIDE", "false").toLowerCase() === "true",
    enableMCP: getEnv("ENABLE_MCP", "true").toLowerCase() === "true",
    mcpTools: getEnv("MCP_TOOLS", "").split(",").map(s => s.trim()).filter(Boolean),
    mcpPrompt: getEnv("MCP_PROMPT", "You have access to the following tools. Use them when appropriate to provide better assistance."),
    enableCLIMode: getEnv("ENABLE_CLI_MODE", "false").toLowerCase() === "true",
    cliPrompt: getEnv("CLI_PROMPT", "You are an AI assistant with full access to the filesystem and command-line tools. You can read, write, edit files, execute commands, and manage the development environment. Always confirm before making destructive operations."),
    storageType: storageType as "kv" | "sqlite" | "memory",
    sqlitePath: getEnv("SQLITE_PATH") || getEnv("DATA_PATH") || "./data/flowith.db",
    serverOnly: getEnv("SERVER_ONLY", "false").toLowerCase() === "true",
    enableClaudeAPI: getEnv("ENABLE_CLAUDE_API", "true").toLowerCase() === "true",
    enableThinkingTags: getEnv("ENABLE_THINKING_TAGS", "true").toLowerCase() === "true",
    thinkingTagFormat: (getEnv("THINKING_TAG_FORMAT", "xml")) as "xml" | "markdown" | "custom",
    thinkingStartTag: getEnv("THINKING_START_TAG", "<thinking>"),
    thinkingEndTag: getEnv("THINKING_END_TAG", "</thinking>"),
    enableStreamOptimization: getEnv("ENABLE_STREAM_OPTIMIZATION", "true").toLowerCase() === "true"
  };
}

// 全局配置对象
let CONFIG = loadConfigFromEnv();

// 保存配置到存储
async function saveConfigToStorage(): Promise<void> {
  if (!storage) return;
  try {
    await storage.set(["config"], CONFIG);
    console.log("[Storage] Configuration saved");
  } catch (e) {
    console.error("[Storage] Failed to save config:", e);
  }
}

// 从存储加载配置
async function loadConfigFromStorage(): Promise<void> {
  if (!storage) return;
  try {
    const value = await storage.get<AppConfig>(["config"]);
    if (value) {
      CONFIG = { ...CONFIG, ...value };
      console.log("[Storage] Configuration loaded");
    }
  } catch (e) {
    console.error("[Storage] Failed to load config:", e);
  }
}

// 兼容性：从配置对象读取值
const TOKENS: string[] = CONFIG.tokens;
const API_KEYS = CONFIG.apiKeys;
const ADMIN_KEY = CONFIG.adminKey;
const PORT = CONFIG.port;
const LOG_LEVEL = CONFIG.logLevel;
const HEADER_TIMEOUT_MS = CONFIG.headerTimeoutMs;
const BODY_TIMEOUT_MS = CONFIG.bodyTimeoutMs;
const STREAM_IDLE_TIMEOUT_MS = CONFIG.streamIdleTimeoutMs;
const STREAM_TOTAL_TIMEOUT_MS = CONFIG.streamTotalTimeoutMs;
const RETRY_MAX = CONFIG.retryMax;
const RETRY_BACKOFF_BASE_MS = CONFIG.retryBackoffBaseMs;
const SSE_RETRY_ON_EMPTY = CONFIG.sseRetryOnEmpty;
const SSE_MIN_CONTENT_LENGTH = CONFIG.sseMinContentLength;
const RETRY_ON_STATUS = new Set(CONFIG.retryOnStatus);
const FLOWITH_BASE = CONFIG.flowithBase;
const FLOWITH_REGION = CONFIG.flowithRegion;
const ORIGIN = CONFIG.origin;
const URL_SEEK = `${ORIGIN}/external/use/knowledge-base/seek`;
const URL_MODELS = `${ORIGIN}/external/use/knowledge-base/models`;
const levels: Record<string, number> = { debug:10, info:20, warn:30, error:40 };
function logAt(level:"debug"|"info"|"warn"|"error", obj:Record<string,unknown>){
  if (levels[level] < levels[LOG_LEVEL]) return;
  console.log(JSON.stringify({ level, ts:new Date().toISOString(), ...obj }));
}
const log = {
  debug:(o:any)=>logAt("debug",o),
  info :(o:any)=>logAt("info",o),
  warn :(o:any)=>logAt("warn",o),
  error:(o:any)=>logAt("error",o),
};
// ============ 数据操作函数 ============
async function loadTokensFromStorage(): Promise<void> {
  if (!storage) return;
  try {
    const value = await storage.get<string[]>(["tokens"]);
    if (value && Array.isArray(value)) {
      TOKENS.length = 0;
      TOKENS.push(...value);
      console.log(`[Storage] Loaded ${TOKENS.length} tokens`);
    }
  } catch (e) {
    console.error("[Storage] Failed to load tokens:", e);
  }
}

async function saveTokensToStorage(): Promise<void> {
  if (!storage) return;
  try {
    await storage.set(["tokens"], TOKENS);
    console.log(`[Storage] Saved ${TOKENS.length} tokens`);
  } catch (e) {
    console.error("[Storage] Failed to save tokens:", e);
  }
}

async function loadStatsFromStorage(): Promise<void> {
  if (!storage) return;
  try {
    const value = await storage.get<{
      totalRequests: number;
      successRequests: number;
      failedRequests: number;
      tokenUsage: Record<string, number>;
      lastResetTime: number;
    }>(["stats"]);
    if (value) {
      stats.totalRequests = value.totalRequests ?? 0;
      stats.successRequests = value.successRequests ?? 0;
      stats.failedRequests = value.failedRequests ?? 0;
      stats.tokenUsage = new Map(Object.entries(value.tokenUsage ?? {}));
      stats.lastResetTime = value.lastResetTime ?? Date.now();
      console.log(`[Storage] Loaded stats: ${stats.totalRequests} total requests`);
    }
  } catch (e) {
    console.error("[Storage] Failed to load stats:", e);
  }
}

async function saveStatsToStorage(): Promise<void> {
  if (!storage) return;
  try {
    await storage.set(["stats"], {
      totalRequests: stats.totalRequests,
      successRequests: stats.successRequests,
      failedRequests: stats.failedRequests,
      tokenUsage: Object.fromEntries(stats.tokenUsage),
                      lastResetTime: stats.lastResetTime
    });
  } catch (e) {
    console.error("[Storage] Failed to save stats:", e);
  }
}

// 添加请求计数器和统计
const stats = {
  totalRequests: 0,
  successRequests: 0,
  failedRequests: 0,
  tokenUsage: new Map<string, number>(),
  lastResetTime: Date.now(),
  // 性能指标
  avgResponseTime: 0,
  totalResponseTime: 0,
  responseCount: 0
};

// 性能统计函数
function recordResponseTime(ms: number) {
  stats.totalResponseTime += ms;
  stats.responseCount++;
  stats.avgResponseTime = Math.round(stats.totalResponseTime / stats.responseCount);
}

interface Session {
  sessionId: string;
  messages: Array<{ role: string; content: string; timestamp: number }>;
  createdAt: number;
  lastAccessedAt: number;
  kbList?: string[];  // 保存 kb_list UUID v4 数组，连续对话时复用
  metadata?: Record<string, any>;
  apiKey?: string;    // 关联的 API key（用于自动会话）
  model?: string;     // 关联的模型（用于自动会话）
}

// 生成自动会话 ID（基于 API key + 模型）
function generateAutoSessionId(apiKey: string, model: string): string {
  const key = `auto_${apiKey}_${model}`.replace(/[^a-zA-Z0-9_-]/g, '_');
  return key.substring(0, 100); // 限制长度
}

class SessionManager {
  private sessions = new Map<string, Session>();

  async getSession(sessionId: string): Promise<Session | null> {
    // 先从内存查找
    let session = this.sessions.get(sessionId);
    if (session) {
      session.lastAccessedAt = Date.now();
      return session;
    }

    if (storage) {
      try {
        const value = await storage.get<Session>(["sessions", sessionId]);
        if (value) {
          session = value;
          session.lastAccessedAt = Date.now();
          this.sessions.set(sessionId, session);
          return session;
        }
      } catch (e) {
        log.error({ 事件: "会话加载失败", sessionId, 错误: String(e) });
      }
    }

    return null;
  }

  async createSession(sessionId: string): Promise<Session> {
    const session: Session = {
      sessionId,
      messages: [],
      createdAt: Date.now(),
      lastAccessedAt: Date.now()
    };
    this.sessions.set(sessionId, session);
    await this.saveSession(session);
    return session;
  }

  async saveSession(session: Session): Promise<void> {
    if (storage) {
      try {
        await storage.set(["sessions", session.sessionId], session, {
          expireIn: CONFIG.contextTTLSeconds * 1000
        });
      } catch (e) {
        log.error({ 事件: "会话保存失败", sessionId: session.sessionId, 错误: String(e) });
      }
    }
  }

  async addMessage(sessionId: string, role: string, content: string, kbList?: string[]): Promise<void> {
    let session = await this.getSession(sessionId);
    if (!session) {
      session = await this.createSession(sessionId);
    }

    session.messages.push({ role, content, timestamp: Date.now() });

    // 保持最大消息数限制
    if (session.messages.length > CONFIG.maxContextMessages) {
      session.messages = session.messages.slice(-CONFIG.maxContextMessages);
    }

    // 更新或设置 kb_list（如果提供）
    if (kbList && kbList.length > 0) {
      session.kbList = kbList;
    }

    await this.saveSession(session);
  }

  async getKbList(sessionId: string): Promise<string[] | undefined> {
    const session = await this.getSession(sessionId);
    return session?.kbList;
  }

  async setKbList(sessionId: string, kbList: string[]): Promise<void> {
    let session = await this.getSession(sessionId);
    if (!session) {
      session = await this.createSession(sessionId);
    }
    session.kbList = kbList;
    await this.saveSession(session);
  }

  async getContext(sessionId: string): Promise<Array<{ role: string; content: string }>> {
    const session = await this.getSession(sessionId);
    if (!session) return [];
    return session.messages.map(({ role, content }) => ({ role, content }));
  }

  async clearSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    if (storage) {
      try {
        await storage.delete(["sessions", sessionId]);
      } catch (e) {
        log.error({ 事件: "会话删除失败", sessionId, 错误: String(e) });
      }
    }
  }

  // 清理过期会话
  async cleanupExpiredSessions(): Promise<void> {
    const now = Date.now();
    const ttl = CONFIG.contextTTLSeconds * 1000;

    for (const [sessionId, session] of this.sessions.entries()) {
      if (now - session.lastAccessedAt > ttl) {
        await this.clearSession(sessionId);
      }
    }
  }
}

const sessionManager = new SessionManager();

// 定期清理过期会话（每5分钟）
if (CONFIG.enableLongContext) {
  setInterval(() => {
    sessionManager.cleanupExpiredSessions().catch(e =>
    log.error({ 事件: "会话清理失败", 错误: String(e) })
    );
  }, 300000);
}

// ============ MCP工具定义 ============
interface MCPTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, any>;
      required: string[];
    };
  };
}

const MCP_TOOLS: MCPTool[] = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search the web for current information. Use this when you need up-to-date facts or recent events.",
      parameters: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "The search query"
          }
        },
        required: ["query"]
      }
    }
  },
{
  type: "function",
  function: {
    name: "image_gen",
    description: "Generate images based on text descriptions. Use this for creating visual content.",
    parameters: {
      type: "object",
      properties: {
        prompt: {
          type: "string",
          description: "Description of the image to generate"
        },
        size: {
          type: "string",
          description: "Image size (e.g., '1024x1024')",
          enum: ["256x256", "512x512", "1024x1024"]
        }
      },
      required: ["prompt"]
    }
  }
},
{
  type: "function",
  function: {
    name: "code_interpreter",
    description: "Execute Python code for calculations, data analysis, or other programming tasks.",
    parameters: {
      type: "object",
      properties: {
        code: {
          type: "string",
          description: "Python code to execute"
        }
      },
      required: ["code"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_read",
    description: "Read the contents of a file. Supports text files and returns the content as a string.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path to the file to read (absolute or relative)"
        }
      },
      required: ["path"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_write",
    description: "Write content to a file. Creates the file if it doesn't exist, overwrites if it does.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path to the file to write (absolute or relative)"
        },
        content: {
          type: "string",
          description: "The content to write to the file"
        }
      },
      required: ["path", "content"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_list",
    description: "List files and directories in a given path. Returns an array of file/directory names.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The directory path to list (defaults to current directory if not provided)"
        },
        recursive: {
          type: "boolean",
          description: "Whether to list files recursively (default: false)"
        }
      },
      required: []
    }
  }
},
{
  type: "function",
  function: {
    name: "bash_execute",
    description: "Execute bash commands in the CLI environment. Use this for running shell commands, git operations, package installations, etc.",
    parameters: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "The bash command to execute"
        },
        timeout: {
          type: "number",
          description: "Timeout in seconds (default: 30)"
        }
      },
      required: ["command"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_edit",
    description: "Edit a specific part of a file by replacing text. Use this to make precise changes to files without rewriting the entire content.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path to the file to edit"
        },
        old_text: {
          type: "string",
          description: "The exact text to search for and replace"
        },
        new_text: {
          type: "string",
          description: "The new text to replace with"
        }
      },
      required: ["path", "old_text", "new_text"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_delete",
    description: "Delete a file from the filesystem. Use with caution as this operation cannot be undone.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path to the file to delete"
        }
      },
      required: ["path"]
    }
  }
},
{
  type: "function",
  function: {
    name: "file_move",
    description: "Move or rename a file. Can be used to reorganize files or change file names.",
    parameters: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "The current path of the file"
        },
        destination: {
          type: "string",
          description: "The new path for the file"
        }
      },
      required: ["source", "destination"]
    }
  }
},
{
  type: "function",
  function: {
    name: "directory_create",
    description: "Create a new directory. Will create parent directories if they don't exist.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path of the directory to create"
        }
      },
      required: ["path"]
    }
  }
},
{
  type: "function",
  function: {
    name: "directory_delete",
    description: "Delete a directory and all its contents. Use with extreme caution as this operation cannot be undone.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The path of the directory to delete"
        },
        recursive: {
          type: "boolean",
          description: "Whether to delete recursively (required for non-empty directories)"
        }
      },
      required: ["path"]
    }
  }
},
{
  type: "function",
  function: {
    name: "search_files",
    description: "Search for text patterns in files using grep-like functionality. Returns matching lines with file paths and line numbers.",
    parameters: {
      type: "object",
      properties: {
        pattern: {
          type: "string",
          description: "The text pattern or regex to search for"
        },
        path: {
          type: "string",
          description: "The directory path to search in (defaults to current directory)"
        },
        file_pattern: {
          type: "string",
          description: "File pattern to filter (e.g., '*.js', '*.py')"
        },
        case_sensitive: {
          type: "boolean",
          description: "Whether the search should be case-sensitive (default: false)"
        }
      },
      required: ["pattern"]
    }
  }
},
{
  type: "function",
  function: {
    name: "get_working_directory",
    description: "Get the current working directory path. Use this to understand where you are in the filesystem.",
    parameters: {
      type: "object",
      properties: {},
      required: []
    }
  }
},
{
  type: "function",
  function: {
    name: "environment_info",
    description: "Get information about the current environment including OS, platform, architecture, and environment variables.",
    parameters: {
      type: "object",
      properties: {
        include_env_vars: {
          type: "boolean",
          description: "Whether to include environment variables (default: false)"
        }
      },
      required: []
    }
  }
},
{
  type: "function",
  function: {
    name: "git_status",
    description: "Get the current git repository status including branch, staged files, unstaged files, and untracked files.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The repository path (defaults to current directory)"
        }
      },
      required: []
    }
  }
},
{
  type: "function",
  function: {
    name: "git_diff",
    description: "Get git diff output to see changes in files. Can show staged or unstaged changes.",
    parameters: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "The repository path (defaults to current directory)"
        },
        staged: {
          type: "boolean",
          description: "Show staged changes (default: false shows unstaged)"
        },
        file: {
          type: "string",
          description: "Specific file to show diff for (optional)"
        }
      },
      required: []
    }
  }
},
{
  type: "function",
  function: {
    name: "file_search",
    description: "Find files by name pattern. Similar to 'find' command but returns a list of matching file paths.",
    parameters: {
      type: "object",
      properties: {
        pattern: {
          type: "string",
          description: "The file name pattern to search for (supports wildcards)"
        },
        path: {
          type: "string",
          description: "The directory path to search in (defaults to current directory)"
        },
        type: {
          type: "string",
          description: "Filter by type: 'file', 'directory', or 'all' (default: 'all')",
          enum: ["file", "directory", "all"]
        }
      },
      required: ["pattern"]
    }
  }
}
];

// CLI工具集名称列表（用于CLI模式自动注入）
const CLI_TOOLS = [
  "file_read",
  "file_write",
  "file_edit",
  "file_delete",
  "file_move",
  "file_list",
  "file_search",
  "directory_create",
  "directory_delete",
  "search_files",
  "bash_execute",
  "get_working_directory",
  "environment_info",
  "git_status",
  "git_diff"
];

// 常用工具集名称列表
const COMMON_TOOLS = [
  "web_search",
  "image_gen",
  "code_interpreter"
];

// 加载初始数据
if (storage) {
  await loadConfigFromStorage();  // 先加载配置
  await loadTokensFromStorage();  // 从存储加载已保存的tokens
  await syncTokensFromEnv(); // 同步环境变量中的tokens（差异或完全同步）
  await loadStatsFromStorage();
  await saveConfigToStorage();  // 保存当前配置（如果存储中没有）
} else {
  // 如果没有存储，也执行环境变量同步（只是不保存）
  const envTokensStr = getEnv("FLOWITH_AUTH_TOKENS");
  const envTokens = Array.from(new Set(
    envTokensStr.split(",").map(s => s.trim()).filter(Boolean)
  ));
  if (envTokens.length > 0 && TOKENS.length === 0) {
    TOKENS.push(...envTokens);
    console.log(`[Sync] Loaded ${TOKENS.length} tokens from environment (no storage)`);
  }
}

// 定期保存统计数据（每30秒）
if (storage) {
  setInterval(() => {
    saveStatsToStorage().catch(e => console.error("[Storage] Auto-save stats failed:", e));
  }, 30000);
}
const mask = (s?:string|null)=>!s?"":(s.length<=8?"***":`${s.slice(0,4)}...${s.slice(-4)}`);
const enc = new TextEncoder(), dec = new TextDecoder();

// ============ 优化的轮询机制 ============
const rrBuf = new SharedArrayBuffer(4);
const rrView = new Int32Array(rrBuf);

// 初始化轮询索引（从0开始）
Atomics.store(rrView, 0, 0);

/**
 * 获取下一个token（按顺序轮询）
 * 实现方式：使用原子操作确保并发安全
 * 第1次请求 -> token[0]
 * 第2次请求 -> token[1]
 * 第3次请求 -> token[2]
 * ...
 * 第N+1次请求 -> token[0]（循环）
 */
function nextToken(): { idx:number, token:string, totalCalls: number } | null {
  const n = TOKENS.length;
  if (n === 0) {
    log.warn({ 事件:"无可用token", 时间: new Date().toISOString() });
    return null;
  }

  // 原子操作：获取当前索引并自增
  const currentIndex = Atomics.load(rrView, 0);
  const nextIndex = (currentIndex + 1) % n;
  Atomics.store(rrView, 0, nextIndex);

  // 获取当前要使用的token
  const idx = currentIndex % n;
  const token = TOKENS[idx];

  // 更新token使用统计
  const maskedToken = mask(token);
  stats.tokenUsage.set(maskedToken, (stats.tokenUsage.get(maskedToken) ?? 0) + 1);

  // 返回详细信息
  return {
    idx,
    token,
    totalCalls: currentIndex + 1  // 总调用次数
  };
}

/**
 * 获取当前轮询状态（不移动索引）
 */
function getCurrentTokenIndex(): number {
  return Atomics.load(rrView, 0) % TOKENS.length;
}

/**
 * 重置轮询索引到指定位置
 */
function resetTokenIndex(index: number = 0): void {
  Atomics.store(rrView, 0, Math.max(0, index));
  log.info({ 事件:"重置轮询索引", 新索引: index });
}
function jsonResponse(obj:any, status=200, extraHeaders?: Record<string, string>){
  return new Response(JSON.stringify(obj), {
    status, headers:{ "content-type":"application/json", ...extraHeaders }
  });
}
function badRequest(msg:string){ return jsonResponse({ error:{ message:msg, type:"bad_request"} }, 400); }
function unauthorized(){ return jsonResponse({ error:{ message:"Unauthorized", type:"auth_error"} }, 401); }
function forbidden(){ return jsonResponse({ error:{ message:"Forbidden", type:"forbidden"} }, 403); }
function gatewayError(e:any){ return jsonResponse({ error:{ message:"Bad Gateway: "+String((e as any)?.message ?? e), type:"network"}}, 502); }
function gatewayTimeout(msg:string){ return jsonResponse({ error:{ message:msg, type:"gateway_timeout"} }, 504); }
function genReqId(h:Headers){ return h.get("x-req-id") ?? crypto.randomUUID(); }
function delay(ms:number){ return new Promise(r=>setTimeout(r,ms)); }
function isAdminAuthorized(req:Request): boolean {
  const auth = req.headers.get("authorization") ?? "";
  const provided = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  // 优先使用 ADMIN_KEY，如果没有则使用 API_KEYS
  if (ADMIN_KEY) {
    return provided === ADMIN_KEY;
  }

  // 如果没有 ADMIN_KEY，则检查 API_KEYS（任何一个 API_KEY 都可以作为管理员）
  if (API_KEYS.length > 0) {
    return API_KEYS.includes(provided);
  }

  return false; // 没有配置任何密钥
}
async function addToken(token:string): Promise<{ success:boolean, message:string }> {
  const trimmed = token.trim();
  if (!trimmed) return { success:false, message:"Token cannot be empty" };
  
  // 使用完整token进行比较，而不是掩码后的token
  const exists = TOKENS.some(existingToken => existingToken === trimmed);
  if (exists) return { success:false, message:"Token already exists" };
  
  TOKENS.push(trimmed);
  await saveTokensToStorage();
  log.info({ 事件:"Token已添加", token: mask(trimmed), 当前总数: TOKENS.length });
  return { success:true, message:"Token added successfully" };
}
async function removeToken(token:string): Promise<{ success:boolean, message:string }> {
  const trimmed = token.trim();
  const idx = TOKENS.indexOf(trimmed);
  if (idx === -1) return { success:false, message:"Token not found" };
  TOKENS.splice(idx, 1);
  await saveTokensToStorage();
  return { success:true, message:"Token removed successfully" };
}
async function addTokensBatch(tokens: string[]): Promise<{ success:boolean, message:string, added:number, skipped:number, failed:string[] }> {
  let added = 0;
  let skipped = 0;
  const failed: string[] = [];

  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) {
      failed.push(`Empty token`);
      continue;
    }
    // 使用完整token进行比较
    const exists = TOKENS.some(existingToken => existingToken === trimmed);
    if (exists) {
      skipped++;
      continue;
    }
    TOKENS.push(trimmed);
    added++;
  }

  if (added > 0) {
    try {
      await saveTokensToStorage();
    } catch (e) {
      // 如果保存失败，回滚已添加的tokens
      TOKENS.splice(-added);
      return {
        success: false,
        message: `Failed to save tokens: ${String(e)}`,
        added: 0,
        skipped,
        failed: [...failed, ...tokens.slice(-added).map(t => `${t} (rollback)`)]
      };
    }
  }

  return {
    success: added > 0,
    message: `Added ${added} tokens, skipped ${skipped} duplicates${failed.length > 0 ? `, ${failed.length} failed` : ''}`,
    added,
    skipped,
    failed
  };
}
async function removeTokensBatch(tokens: string[]): Promise<{ success:boolean, message:string, removed:number, notFound:number }> {
  let removed = 0;
  let notFound = 0;

  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) continue;

    const idx = TOKENS.indexOf(trimmed);
    if (idx === -1) {
      notFound++;
      continue;
    }
    TOKENS.splice(idx, 1);
    removed++;
  }

  if (removed > 0) {
    await saveTokensToStorage();
  }

  return {
    success: removed > 0,
    message: `Removed ${removed} tokens${notFound > 0 ? `, ${notFound} not found` : ''}`,
    removed,
    notFound
  };
}
async function clearAllTokens(): Promise<{ success:boolean, message:string, cleared:number }> {
  const count = TOKENS.length;
  TOKENS.length = 0;
  await saveTokensToStorage();
  return {
    success: true,
    message: `Cleared ${count} tokens`,
    cleared: count
  };
}

// 启动时同步环境变量中的tokens
async function syncTokensFromEnv(): Promise<void> {
  const envTokensStr = getEnv("FLOWITH_AUTH_TOKENS");
  const envTokens = Array.from(new Set(
    envTokensStr.split(",").map(s => s.trim()).filter(Boolean)
  ));

  const rsyncMode = getEnv("RSYNC", "0").trim() === "1";

  if (envTokens.length === 0) {
    console.log("[Sync] No tokens in environment variable, skipping sync");
    return;
  }

  if (rsyncMode) {
    // 完全同步模式：清空存储，完全替换
    console.log(`[Sync] RSYNC mode enabled: clearing all tokens and loading ${envTokens.length} tokens from environment`);
    TOKENS.length = 0;
    TOKENS.push(...envTokens);
    await saveTokensToStorage();
    console.log(`[Sync] Full sync completed: ${TOKENS.length} tokens loaded`);
  } else {
    // 差异同步模式：只添加新的token，保留存储中已有的
    const existingSet = new Set(TOKENS);
    const newTokens: string[] = [];

    for (const token of envTokens) {
      if (!existingSet.has(token)) {
        TOKENS.push(token);
        newTokens.push(token);
      }
    }

    if (newTokens.length > 0) {
      await saveTokensToStorage();
      console.log(`[Sync] Differential sync completed: added ${newTokens.length} new tokens, total ${TOKENS.length} tokens`);
    } else {
      console.log(`[Sync] Differential sync completed: no new tokens to add, total ${TOKENS.length} tokens`);
    }
  }
}

async function fetchWithHeaderTimeout(input: Request|string, init: RequestInit & { headerTimeoutMs:number, logCtx:any }){
  const { headerTimeoutMs, logCtx, ...rest } = init;
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(new Error("upstream header timeout")), headerTimeoutMs);
  
  // 代理支持：Deno会自动读取环境变量HTTP_PROXY/HTTPS_PROXY
  // 如果配置了PROXY_URL，设置到环境变量中
  if (CONFIG.proxyUrl && !getEnv("HTTP_PROXY") && !getEnv("HTTPS_PROXY")) {
    try {
      Deno.env.set("HTTP_PROXY", CONFIG.proxyUrl);
      Deno.env.set("HTTPS_PROXY", CONFIG.proxyUrl);
      log.debug({ 事件:"代理配置", 代理URL: CONFIG.proxyUrl });
    } catch (e) {
      // 非Deno环境，忽略代理设置错误
      log.debug({ 事件:"代理配置跳过", 原因: "非Deno环境" });
    }
  }
  
  const startTime = Date.now();
  try{
    log.debug({ 
      事件:"上游请求", 
      方法:(rest.method ?? "GET"), 
      URL: typeof input==="string"? input : (input as Request).url,
      ...logCtx 
    });
    
    const resp = await fetch(input, { ...rest, signal: controller.signal });
    clearTimeout(timer);
    
    const elapsed = Date.now() - startTime;
    log.info({
      事件:"上游响应",
      状态: resp.status,
      类型: resp.headers.get("content-type")?.split(";")[0] ?? "",
      耗时ms: elapsed,
             ...logCtx
    });
    return resp;
  }catch(e){
    clearTimeout(timer);
    const elapsed = Date.now() - startTime;
    log.warn({ 事件:"上游请求失败", 错误:String((e as any)?.message ?? e), 耗时ms: elapsed, ...logCtx });
    throw e;
  }
}
function withTimeout<T>(p: Promise<T>, ms: number, label = "timeout", logCtx?:any): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => {
      log.warn({ 事件:"Promise超时", 标签:label, 限时ms:ms, ...logCtx });
      reject(new Error(label));
    }, ms);
    p.then(v => { clearTimeout(t); resolve(v); }, e => { clearTimeout(t); reject(e); });
  });
}
// 缓存OpenAI格式对象以减少重复创建
const openaiChunkCache = new Map<string, any>();
function openaiChunk(model:string, textDelta:string){
  // 对于空内容或长内容不缓存
  if (!textDelta || textDelta.length > 100) {
    return { 
      id: "chatcmpl_" + Math.random().toString(36).slice(2), 
      object:"chat.completion.chunk",
      created: Math.floor(Date.now()/1000), 
      model,
      choices:[{ index:0, delta:{ content:textDelta }, finish_reason:null }] 
    };
  }
  
  const cacheKey = `${model}:${textDelta}`;
  if (openaiChunkCache.has(cacheKey)) {
    return openaiChunkCache.get(cacheKey);
  }
  
  const chunk = { 
    id: "chatcmpl_" + Math.random().toString(36).slice(2), 
    object:"chat.completion.chunk",
    created: Math.floor(Date.now()/1000), 
    model,
    choices:[{ index:0, delta:{ content:textDelta }, finish_reason:null }] 
  };
  
  // 限制缓存大小
  if (openaiChunkCache.size < 1000) {
    openaiChunkCache.set(cacheKey, chunk);
  }
  
  return chunk;
}

function openaiNonStream(model:string, content:string){
  return { id: "chatcmpl_" + Math.random().toString(36).slice(2), object:"chat.completion",
    created: Math.floor(Date.now()/1000), model,
    choices:[{ index:0, message:{ role:"assistant", content }, finish_reason:"stop" }], usage:null };
}
function extractTextFromPart(part:any):string{
  if (part==null) return "";
  if (typeof part==="string") return part;
  if (typeof part==="object"){
    const t = (part.type ?? "").toString().toLowerCase();
    if (t==="text" || t==="input_text") return typeof part.text==="string" ? part.text : String(part?.text ?? "");
  }
  return "";
}
function flattenContent(content:any):string{
  if (content==null) return "";
  if (typeof content==="string") return content;
  if (Array.isArray(content)) return content.map(extractTextFromPart).filter(Boolean).join("\n\n").trim();
  if (typeof content==="object") return extractTextFromPart(content).trim();
  return String(content);
}
function normalizeMessages(messages:any[]){ return messages.map(m=>({ role:(m?.role ?? "user").toString(), content: flattenContent(m?.content) })); }
function extractDeltaFromTextChunk(raw: string): { delta: string; isFinal: boolean } {
  let s = (raw ?? "").trim();
  if (!s) return { delta: "", isFinal: false };
  if (s.startsWith("data:")) s = s.slice(5).trim();
  try {
    const obj = JSON.parse(s);
    const text = typeof obj?.content === "string" ? obj.content
    : typeof obj?.answer  === "string" ? obj.answer
    : typeof obj?.message === "string" ? obj.message
    : typeof obj?.text    === "string" ? obj.text
    : "";
    const isFinal = (obj?.tag === "final") || (obj?.finish_reason === "stop");
    if (text) return { delta: text, isFinal };
  } catch {}
  const m = s.match(/"content"\s*:\s*"([^"]*)"/);
  if (m) return { delta: m[1], isFinal: /"tag"\s*:\s*"final"/.test(s) };
  return { delta: s, isFinal: false };
}
async function incrementallyReadPlainText(
  resp: Response,
  logCtx: any,
  idleMs: number,
  totalMs: number
): Promise<{ content: string; status: number; headers: Headers }> {
  const body = resp.body as ReadableStream<Uint8Array> | null;
  if (!body) return { content: "", status: resp.status, headers: resp.headers };

  const reader = body.getReader();
  let idleTimer: number | undefined;
  let totalTimer: number | undefined;
  let readerClosed = false;
  let buf = "";
  let content = "";

  const resetIdle = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      log.warn({ 事件:"上游plain空闲超时(增量)", 空闲毫秒: idleMs, ...logCtx });
      try { reader.cancel("idle timeout"); } catch {}
      readerClosed = true;
    }, idleMs) as unknown as number;
  };
  const startTotal = () => {
    totalTimer = setTimeout(() => {
      log.warn({ 事件:"上游plain总时限触发(增量)", 总毫秒: totalMs, ...logCtx });
      try { reader.cancel("total timeout"); } catch {}
      readerClosed = true;
    }, totalMs) as unknown as number;
  };

  resetIdle();
  startTotal();

  try {
    while (!readerClosed) {
      const { done, value } = await reader.read();
      if (done) break;

      resetIdle();
      buf += dec.decode(value, { stream:true });

      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const { delta, isFinal } = extractDeltaFromTextChunk(chunk);
        log.debug({ 事件:"上游plain分片", 原文预览: chunk.slice(0, 200), 提取: delta.slice(0, 200), ...logCtx });
        if (delta) content += delta;
        if (isFinal) { readerClosed = true; break; }
      }

      let lineIdx;
      while (!readerClosed && (lineIdx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, lineIdx); buf = buf.slice(lineIdx + 1);
        const { delta, isFinal } = extractDeltaFromTextChunk(line);
        if (delta) content += delta;
        if (isFinal) { readerClosed = true; break; }
      }

      let braceIdx;
      while (!readerClosed && (braceIdx = buf.indexOf("}\n")) !== -1) {
        const jsonLike = buf.slice(0, braceIdx + 1); buf = buf.slice(braceIdx + 2);
        const { delta, isFinal } = extractDeltaFromTextChunk(jsonLike);
        if (delta) content += delta;
        if (isFinal) { readerClosed = true; break; }
      }
    }
  } catch (e) {
    log.warn({ 事件:"上游plain读取异常(增量)", 错误:String((e as any)?.message ?? e), ...logCtx });
  } finally {
    if (idleTimer)  clearTimeout(idleTimer);
    if (totalTimer) clearTimeout(totalTimer);
    try { reader.releaseLock(); } catch {}
  }

  if (buf.trim()) {
    const { delta } = extractDeltaFromTextChunk(buf);
    if (delta) content += delta;
  }

  log.info({ 事件:"上游plain聚合完成", 字数: content.length, ...logCtx });
  return { content, status: resp.status, headers: resp.headers };
}
async function aggregateFromStreamResponse(args: { resp: Response, logCtx:any, modelName:string })
: Promise<{ kind:"nonstream", status:number, content:string, headers: Headers, isEmpty?: boolean, isTruncated?: boolean }>
{
  const { resp, logCtx, modelName } = args;
  const body = resp.body as ReadableStream<Uint8Array> | null;
  if (!body) {
    log.warn({ 事件:"上游SSE无body", ...logCtx });
    return { kind:"nonstream", status: resp.status, content: "", headers: resp.headers, isEmpty: true };
  }

  let idleTimer: number | undefined;
  let totalTimer: number | undefined;
  let content = "";
  let readerClosed = false;
  let isTruncated = false;
  let chunkCount = 0;
  const reader = body.getReader();

  const resetIdle = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      log.warn({ 事件:"上游SSE空闲超时(聚合)", 空闲毫秒: STREAM_IDLE_TIMEOUT_MS, 已接收块数: chunkCount, 内容长度: content.length, ...logCtx });
      isTruncated = true;
      try { reader.cancel("idle timeout"); } catch {}
      readerClosed = true;
    }, STREAM_IDLE_TIMEOUT_MS) as unknown as number;
  };
  const startTotal = () => {
    totalTimer = setTimeout(() => {
      log.warn({ 事件:"上游SSE总时限触发(聚合)", 总毫秒: STREAM_TOTAL_TIMEOUT_MS, 已接收块数: chunkCount, 内容长度: content.length, ...logCtx });
      isTruncated = true;
      try { reader.cancel("total timeout"); } catch {}
      readerClosed = true;
    }, STREAM_TOTAL_TIMEOUT_MS) as unknown as number;
  };

  resetIdle();
  startTotal();

  let buf = "";
  try {
    while (!readerClosed) {
      const { done, value } = await reader.read();
      if (done) break;
      resetIdle();
      chunkCount++;
      buf += dec.decode(value, { stream:true });

      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const evt = buf.slice(0, idx); buf = buf.slice(idx+2);
        const dataLines = evt.split("\n")
        .map(l => l.trimEnd())
        .filter(l => l.startsWith("data:"))
        .map(l => l.slice(5).trim());
        if (dataLines.length === 0) continue;

        const data = dataLines.join("\n");
        log.debug({ 事件:"上游SSE分片(聚合)", 原文预览: data.slice(0, 200), 块序号: chunkCount, ...logCtx });

        // 检查是否为 [DONE] 标记（非JSON格式）
        if (data === "[DONE]") {
          log.debug({ 事件:"收到[DONE]标记", ...logCtx });
          readerClosed = true;
          break;
        }

        try {
          const obj = JSON.parse(data);
          // Flowith格式：每个chunk都有tag:final，只有content为"[DONE]"时才真正结束
          if (obj?.tag === "seeds") {
            // seeds标记，跳过
            log.debug({ 事件:"收到seeds标记", 内容: obj.content, ...logCtx });
            continue;
          }

          if (obj?.tag === "final") {
            const delta = typeof obj?.content === "string" ? obj.content : String(obj.content ?? "");
            // 检查是否为结束标记
            if (delta === "[DONE]") {
              log.debug({ 事件:"收到final+[DONE]标记", ...logCtx });
              readerClosed = true;
              break;
            }
            // 正常内容，累加
            if (delta) content += delta;
          } else {
            // 其他格式兼容
            const delta = typeof obj?.content === "string" ? obj.content : "";
            if (delta) content += delta;
          }
        } catch {
          // JSON解析失败，尝试提取文本
          const { delta, isFinal } = extractDeltaFromTextChunk(data);
          if (delta && delta !== "[DONE]") content += delta;
          if (isFinal || delta === "[DONE]") { readerClosed = true; break; }
        }
      }
    }
  } catch (e) {
    log.warn({ 事件:"上游SSE读取异常(聚合)", 错误:String((e as any)?.message ?? e), 已接收块数: chunkCount, ...logCtx });
    isTruncated = true;
  } finally {
    if (idleTimer)  clearTimeout(idleTimer);
    if (totalTimer) clearTimeout(totalTimer);
    try { reader.releaseLock(); } catch {}
  }

  const isEmpty = content.length < SSE_MIN_CONTENT_LENGTH;
  if (isEmpty || isTruncated) {
    log.warn({
      事件:"上游SSE异常结束",
      字数: content.length,
      块数: chunkCount,
      是否为空: isEmpty,
      是否截断: isTruncated,
      ...logCtx
    });
  } else {
    log.info({ 事件:"上游SSE聚合完成", 字数: content.length, 块数: chunkCount, ...logCtx });
  }

  return { kind:"nonstream", status: resp.status, content, headers: resp.headers, isEmpty, isTruncated };
}
async function callUpstreamChat(opts: {
  reqId: string,
  token: string,
  body: any,
  forceStream?: boolean,
    isExternalStream: boolean,
    modelName: string
}): Promise<{ kind:"stream", resp: Response } | { kind:"nonstream", status: number, content: string, headers: Headers, isEmpty?: boolean, isTruncated?: boolean }> {
  const { reqId, token, body, forceStream=false, isExternalStream, modelName } = opts;
  const logCtx = { 请求ID:reqId, 模型: modelName, token: mask(token) };

  const upstreamStream = forceStream ? true : !!body?.stream;

  const started = Date.now();
  const resp = await fetchWithHeaderTimeout(URL_SEEK, {
    method:"POST",
    headers:{
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      "Accept": upstreamStream ? "text/event-stream":"application/json",
      "X-Request-ID": reqId,
    },
    body: JSON.stringify({ ...body, stream: upstreamStream }),
                                            headerTimeoutMs: HEADER_TIMEOUT_MS,
                                            logCtx: { ...logCtx, 上游: URL_SEEK, 流式: upstreamStream }
  });

  log.info({
    事件:"上游响应(seek)",
           状态: resp.status,
           时延ms: Date.now()-started,
           ...logCtx
  });

  const status = resp.status;
  const ct = (resp.headers.get("content-type") ?? "").toLowerCase();

  // 对于外部流式请求，无论上游返回什么content-type都需要转换为标准SSE格式
  // 因为上游可能返回 text/plain，需要统一处理
  if (isExternalStream && upstreamStream) {
    // 不再直接透传，而是进行格式转换
    return { kind:"stream", resp };
  }

  if (status < 200 || status >= 300) {
    let txt = "";
    try { txt = await withTimeout(resp.text(), BODY_TIMEOUT_MS, "upstream body timeout (error)", logCtx); }
    catch (e) { log.warn({ 事件:"上游错误体读取失败", 错误:String((e as any)?.message ?? e), ...logCtx }); }
    log.warn({ 事件:"上游非2xx", 状态: status, 错误体预览: txt.slice(0,500), ...logCtx });
    return { kind:"nonstream", status, content: txt || `HTTP ${status}`, headers: resp.headers };
  }

  if (!upstreamStream) {
    try {
      if (ct.includes("application/json")) {
        const raw = await withTimeout(resp.text(), BODY_TIMEOUT_MS, "upstream body timeout (json)", logCtx);
        log.debug({ 事件:"上游响应体(JSON原文)", 预览: raw.slice(0,500), 长度: raw.length, ...logCtx });
        const j = JSON.parse(raw);
        const content = String(j?.content ?? j?.answer ?? j?.message ?? j?.text ?? "") || raw;
        return { kind:"nonstream", status, content, headers: resp.headers };
      } else if (ct.includes("text/plain")) {
        const result = await incrementallyReadPlainText(resp, logCtx, STREAM_IDLE_TIMEOUT_MS, STREAM_TOTAL_TIMEOUT_MS);
        return { kind:"nonstream", status: result.status, content: result.content, headers: result.headers };
      } else {
        const raw = await withTimeout(resp.text(), BODY_TIMEOUT_MS, "upstream body timeout (text)", logCtx);
        log.debug({ 事件:"上游响应体(TEXT)", 预览: raw.slice(0,500), 长度: raw.length, ...logCtx });
        return { kind:"nonstream", status, content: raw, headers: resp.headers };
      }
    } catch (e) {
      log.warn({ 事件:"上游读取超时", 错误:String((e as any)?.message ?? e), ...logCtx });
      const resp2 = await fetchWithHeaderTimeout(URL_SEEK, {
        method:"POST",
        headers:{
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
          "Accept": "text/event-stream",
          "X-Request-ID": reqId,
        },
        body: JSON.stringify({ ...body, stream: true }),
                                                 headerTimeoutMs: HEADER_TIMEOUT_MS,
                                                 logCtx: { ...logCtx, 上游: URL_SEEK, 流式: true, 兜底:true }
      });
      if (resp2.status < 200 || resp2.status >= 300) {
        let txt = "";
        try { txt = await withTimeout(resp2.text(), BODY_TIMEOUT_MS, "upstream body timeout (force-stream error)", logCtx); } catch {}
        return { kind:"nonstream", status: resp2.status, content: txt || `HTTP ${resp2.status}`, headers: resp2.headers };
      }
      return await aggregateFromStreamResponse({ resp: resp2, logCtx, modelName });
    }
  } else {
    return await aggregateFromStreamResponse({ resp, logCtx, modelName });
  }
}
serve(async (req:Request): Promise<Response> => {
  const url = new URL(req.url);
  const path = url.pathname;
  const reqId = genReqId(req.headers);

  // 仅服务端模式：跳过API_KEYS鉴权，直接透传下游的Authorization
  const serverOnlyMode = CONFIG.serverOnly;
  let downstreamToken: string | null = null;

  if (serverOnlyMode) {
    // 提取下游传来的token用于透传
    const auth = req.headers.get("authorization") ?? "";
    const xApiKey = req.headers.get("x-api-key") ?? "";

    if (auth.startsWith("Bearer ")) {
      downstreamToken = auth.slice(7);
    } else if (xApiKey) {
      // 支持Claude格式的x-api-key
      downstreamToken = xApiKey;
    }
  } else {
    // 正常模式：需要鉴权（支持Bearer和x-api-key两种格式）
    if (API_KEYS.length > 0){
      const auth = req.headers.get("authorization") ?? "";
      const xApiKey = req.headers.get("x-api-key") ?? "";

      let provided = "";
      if (auth.startsWith("Bearer ")) {
        provided = auth.slice(7);
      } else if (xApiKey) {
        provided = xApiKey;
      }

      if (!provided || !API_KEYS.includes(provided)){
        log.warn({ 事件:"鉴权失败", 请求ID: reqId });
        return unauthorized();
      }
    }
  }

  stats.totalRequests++;
  
  // 简化日志：仅记录关键信息
  const logData: Record<string, any> = {
    事件:"入站请求",
    ID:reqId,
    方法:req.method,
    路径:path
  };
  
  // 仅在debug模式下打印详细信息
  if (LOG_LEVEL === "debug") {
  const preview = (req.method === "POST" || req.method === "PUT" || req.method === "PATCH")
  ? await req.clone().text().catch(()=> "")
  : "";
    logData.请求体预览 = preview.slice(0, 200);
    logData.UA = req.headers.get("user-agent")?.slice(0, 50) ?? "";
  }
  
  log.info(logData);

  try{
    /* 健康检查与状态 */
    if (req.method==="GET" && (path==="/__healthz" || path==="/healthz")) {
      return jsonResponse({ ok:true });
    }
    if (req.method==="GET" && path==="/v1/status"){
      return jsonResponse({
        status:"ok",
        version: "v4.0.0",
        origin: ORIGIN,
        tokens: TOKENS.map((t, i) => ({
          index: i,
          token: mask(t),
                                      is_current: i === getCurrentTokenIndex(),
                                      usage_count: stats.tokenUsage.get(mask(t)) ?? 0
        })),
        tokens_count: TOKENS.length,
        current_token_index: getCurrentTokenIndex(),
                          total_token_calls: Atomics.load(rrView,0),
                          features: {
                            long_context: CONFIG.enableLongContext,
                            thinking_injection: CONFIG.enableThinkingInjection,
                            mcp_tools: CONFIG.enableMCP,
                            cli_mode: CONFIG.enableCLIMode,
                            server_only_mode: CONFIG.serverOnly,
                            claude_api: CONFIG.enableClaudeAPI,
                            storage: {
                              type: STORAGE_TYPE,
                              active: storage !== null
                            }
                          },
                          config: {
                            max_context_messages: CONFIG.maxContextMessages,
                            context_ttl_seconds: CONFIG.contextTTLSeconds,
                            mcp_tools: CONFIG.mcpTools,
                            sse_retry_on_empty: CONFIG.sseRetryOnEmpty,
                            sse_min_content_length: CONFIG.sseMinContentLength,
                            proxy_url: CONFIG.proxyUrl ? "已配置" : "未配置"
                          },
                          stats: {
                            total_requests: stats.totalRequests,
                            success_requests: stats.successRequests,
                            failed_requests: stats.failedRequests,
                            success_rate: stats.totalRequests > 0 ? ((stats.successRequests / stats.totalRequests) * 100).toFixed(2) + "%" : "N/A",
                            avg_response_time_ms: stats.avgResponseTime,
                            total_response_count: stats.responseCount,
                          uptime_seconds: Math.floor((Date.now() - stats.lastResetTime) / 1000),
                          token_usage: Object.fromEntries(stats.tokenUsage)
                          },
                          timeouts: { HEADER_TIMEOUT_MS, BODY_TIMEOUT_MS, STREAM_IDLE_TIMEOUT_MS, STREAM_TOTAL_TIMEOUT_MS },
                          retry: { RETRY_MAX, RETRY_BACKOFF_BASE_MS, RETRY_ON_STATUS: Array.from(RETRY_ON_STATUS) }
      });
    }

    /* Token批量管理API - 需要管理员权限 */
    if (path==="/v1/admin/tokens/batch"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      // POST: 批量添加tokens
      if (req.method==="POST"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }

        let tokensToAdd: string[] = [];

        // 支持两种格式：
        // 1. { "tokens": ["token1", "token2", ...] }
        // 2. { "tokens": "token1,token2,token3" } - 逗号分隔的字符串
        if (body.tokens) {
          if (Array.isArray(body.tokens)) {
            tokensToAdd = body.tokens;
          } else if (typeof body.tokens === "string") {
            tokensToAdd = body.tokens.split(",").map((t: string) => t.trim()).filter(Boolean);
          } else {
            return badRequest("`tokens` must be an array or comma-separated string.");
          }
        } else {
          return badRequest("`tokens` field is required.");
        }

        if (tokensToAdd.length === 0) {
          return badRequest("No valid tokens provided.");
        }

        const result = await addTokensBatch(tokensToAdd);
        log.info({
          事件:"批量添加tokens",
          请求ID:reqId,
          提供数量: tokensToAdd.length,
          添加: result.added,
          跳过: result.skipped,
          失败: result.failed.length,
          当前总数: TOKENS.length
        });

        return jsonResponse({
          ...result,
          tokens_count: TOKENS.length,
          details: {
            provided: tokensToAdd.length,
            current_total: TOKENS.length
          }
        }, result.success ? 200 : 400);
      }

      // DELETE: 批量删除tokens
      if (req.method==="DELETE"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }

        let tokensToRemove: string[] = [];

        // 支持两种格式：
        // 1. { "tokens": ["token1", "token2", ...] }
        // 2. { "tokens": "token1,token2,token3" } - 逗号分隔的字符串
        if (body.tokens) {
          if (Array.isArray(body.tokens)) {
            tokensToRemove = body.tokens;
          } else if (typeof body.tokens === "string") {
            tokensToRemove = body.tokens.split(",").map((t: string) => t.trim()).filter(Boolean);
          } else {
            return badRequest("`tokens` must be an array or comma-separated string.");
          }
        } else {
          return badRequest("`tokens` field is required.");
        }

        if (tokensToRemove.length === 0) {
          return badRequest("No valid tokens provided.");
        }

        const result = await removeTokensBatch(tokensToRemove);
        log.info({
          事件:"批量删除tokens",
          请求ID:reqId,
          提供数量: tokensToRemove.length,
          删除: result.removed,
          未找到: result.notFound,
          当前总数: TOKENS.length
        });

        return jsonResponse({
          ...result,
          tokens_count: TOKENS.length
        }, result.success ? 200 : 404);
      }

      return jsonResponse({ error:{ message:"Method not allowed", type:"method_not_allowed"} }, 405);
    }

    /* 清空所有tokens - 需要管理员权限 */
    if (path==="/v1/admin/tokens/clear"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      if (req.method==="POST"){
        const result = await clearAllTokens();
        log.info({ 事件:"清空所有tokens", 请求ID:reqId, 清空数量: result.cleared });
        return jsonResponse(result);
      }

      return jsonResponse({ error:{ message:"Method not allowed", type:"method_not_allowed"} }, 405);
    }

    /* Token管理API - 需要管理员权限 */
    if (path==="/v1/admin/tokens"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      // GET: 列出所有tokens（带掩码和详细信息）
      if (req.method==="GET"){
        log.info({ 事件:"列出tokens", 请求ID:reqId, 数量: TOKENS.length });
        return jsonResponse({
          success: true,
          tokens: TOKENS.map((t, i) => ({
            index: i,
            token: mask(t),
                                        length: t.length,
                                        is_current: i === getCurrentTokenIndex(),
                                        usage_count: stats.tokenUsage.get(mask(t)) ?? 0,
                                        next_in_queue: i === (getCurrentTokenIndex() + 1) % TOKENS.length
          })),
          count: TOKENS.length,
          current_index: getCurrentTokenIndex(),
                            total_calls: Atomics.load(rrView,0)
        });
      }

      // POST: 添加token
      if (req.method==="POST"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }
        const { token } = body;
        if (!token || typeof token !== "string") return badRequest("`token` is required and must be a string.");

        const result = await addToken(token);
        log.info({ 事件:"添加token", 请求ID:reqId, 成功: result.success, 消息: result.message, 当前数量: TOKENS.length });
        return jsonResponse({ ...result, tokens_count: TOKENS.length }, result.success ? 200 : 400);
      }

      // DELETE: 删除token
      if (req.method==="DELETE"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }
        const { token } = body;
        if (!token || typeof token !== "string") return badRequest("`token` is required and must be a string.");

        const result = await removeToken(token);
        log.info({ 事件:"删除token", 请求ID:reqId, 成功: result.success, 消息: result.message, 当前数量: TOKENS.length });
        return jsonResponse({ ...result, tokens_count: TOKENS.length }, result.success ? 200 : 404);
      }

      // PUT: 重置轮询索引
      if (req.method==="PUT"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }
        const { index } = body;

        if (typeof index === "number") {
          if (index < 0 || index >= TOKENS.length) {
            return badRequest(`Index must be between 0 and ${TOKENS.length - 1}`);
          }
          resetTokenIndex(index);
          log.info({ 事件:"重置token索引", 请求ID:reqId, 新索引: index });
          return jsonResponse({
            success: true,
            message: "Token index reset successfully",
            new_index: index,
            next_token: mask(TOKENS[index])
          });
        }

        return badRequest("`index` is required and must be a number.");
      }

      return jsonResponse({ error:{ message:"Method not allowed", type:"method_not_allowed"} }, 405);
    }

    /* 重置统计信息 - 需要管理员权限 */
    if (req.method==="POST" && path==="/v1/admin/stats/reset"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      const oldStats = {
        total_requests: stats.totalRequests,
        success_requests: stats.successRequests,
        failed_requests: stats.failedRequests
      };

      stats.totalRequests = 0;
      stats.successRequests = 0;
      stats.failedRequests = 0;
      stats.tokenUsage.clear();
      stats.lastResetTime = Date.now();

      await saveStatsToStorage(); // 重置后保存

      log.info({ 事件:"重置统计信息", 请求ID:reqId, 旧统计: oldStats });
      return jsonResponse({ success: true, message: "Statistics reset successfully", old_stats: oldStats });
    }

    /* 配置管理API - 需要管理员权限 */
    if (path==="/v1/admin/config"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      // GET: 查看当前配置
      if (req.method==="GET"){
        return jsonResponse({
          success: true,
          config: {
            // 基础配置（敏感信息已隐藏）
            port: CONFIG.port,
            logLevel: CONFIG.logLevel,
            origin: CONFIG.origin,
            storageType: CONFIG.storageType,
            
            // 超时配置
            headerTimeoutMs: CONFIG.headerTimeoutMs,
            bodyTimeoutMs: CONFIG.bodyTimeoutMs,
            streamIdleTimeoutMs: CONFIG.streamIdleTimeoutMs,
            streamTotalTimeoutMs: CONFIG.streamTotalTimeoutMs,
            
            // 重试配置
            retryMax: CONFIG.retryMax,
            retryBackoffBaseMs: CONFIG.retryBackoffBaseMs,
            sseRetryOnEmpty: CONFIG.sseRetryOnEmpty,
            sseMinContentLength: CONFIG.sseMinContentLength,
            noRetryOnTimeout: CONFIG.noRetryOnTimeout,
            
            // 上下文配置
            enableLongContext: CONFIG.enableLongContext,
            maxContextMessages: CONFIG.maxContextMessages,
            contextTTLSeconds: CONFIG.contextTTLSeconds,
            
            // 系统提示词配置
            enableThinkingInjection: CONFIG.enableThinkingInjection,
            enableSystemPromptOverride: CONFIG.enableSystemPromptOverride,
            
            // MCP配置
            enableMCP: CONFIG.enableMCP,
            mcpTools: CONFIG.mcpTools,
            
            // CLI模式配置
            enableCLIMode: CONFIG.enableCLIMode,
            availableCliTools: CLI_TOOLS.length,
            
            // 思考功能配置
            enableThinkingTags: CONFIG.enableThinkingTags,
            thinkingTagFormat: CONFIG.thinkingTagFormat,
            
            // 其他功能
            serverOnly: CONFIG.serverOnly,
            enableClaudeAPI: CONFIG.enableClaudeAPI,
            enableStreamOptimization: CONFIG.enableStreamOptimization,
            proxyConfigured: !!CONFIG.proxyUrl
          }
        });
      }

      // PATCH: 更新配置（部分更新）
      if (req.method==="PATCH"){
        let body:any = {};
        try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }

        const updates: string[] = [];
        
        // 允许更新的配置项
        if (typeof body.logLevel === "string") {
          CONFIG.logLevel = body.logLevel.toLowerCase();
          updates.push("logLevel");
        }
        if (typeof body.retryMax === "number") {
          CONFIG.retryMax = Math.max(0, body.retryMax);
          updates.push("retryMax");
        }
        if (typeof body.retryBackoffBaseMs === "number") {
          CONFIG.retryBackoffBaseMs = Math.max(0, body.retryBackoffBaseMs);
          updates.push("retryBackoffBaseMs");
        }
        if (typeof body.enableLongContext === "boolean") {
          CONFIG.enableLongContext = body.enableLongContext;
          updates.push("enableLongContext");
        }
        if (typeof body.maxContextMessages === "number") {
          CONFIG.maxContextMessages = Math.max(1, body.maxContextMessages);
          updates.push("maxContextMessages");
        }
        if (typeof body.contextTTLSeconds === "number") {
          CONFIG.contextTTLSeconds = Math.max(60, body.contextTTLSeconds);
          updates.push("contextTTLSeconds");
        }
        if (typeof body.enableThinkingInjection === "boolean") {
          CONFIG.enableThinkingInjection = body.enableThinkingInjection;
          updates.push("enableThinkingInjection");
        }
        if (typeof body.thinkingPrompt === "string") {
          CONFIG.thinkingPrompt = body.thinkingPrompt;
          updates.push("thinkingPrompt");
        }
        if (typeof body.systemPrompt === "string") {
          CONFIG.systemPrompt = body.systemPrompt;
          updates.push("systemPrompt");
        }
        if (typeof body.enableSystemPromptOverride === "boolean") {
          CONFIG.enableSystemPromptOverride = body.enableSystemPromptOverride;
          updates.push("enableSystemPromptOverride");
        }
        if (typeof body.enableMCP === "boolean") {
          CONFIG.enableMCP = body.enableMCP;
          updates.push("enableMCP");
        }
        if (Array.isArray(body.mcpTools)) {
          CONFIG.mcpTools = body.mcpTools.filter((t: any) => typeof t === "string");
          updates.push("mcpTools");
        }
        if (typeof body.mcpPrompt === "string") {
          CONFIG.mcpPrompt = body.mcpPrompt;
          updates.push("mcpPrompt");
        }
        if (typeof body.enableThinkingTags === "boolean") {
          CONFIG.enableThinkingTags = body.enableThinkingTags;
          updates.push("enableThinkingTags");
        }
        if (typeof body.sseRetryOnEmpty === "boolean") {
          CONFIG.sseRetryOnEmpty = body.sseRetryOnEmpty;
          updates.push("sseRetryOnEmpty");
        }
        if (typeof body.noRetryOnTimeout === "boolean") {
          CONFIG.noRetryOnTimeout = body.noRetryOnTimeout;
          updates.push("noRetryOnTimeout");
        }
        if (typeof body.enableCLIMode === "boolean") {
          CONFIG.enableCLIMode = body.enableCLIMode;
          updates.push("enableCLIMode");
        }
        if (typeof body.cliPrompt === "string") {
          CONFIG.cliPrompt = body.cliPrompt;
          updates.push("cliPrompt");
        }

        if (updates.length === 0) {
          return badRequest("No valid configuration updates provided.");
        }

        // 保存配置到存储
        await saveConfigToStorage();

        log.info({ 事件:"配置更新", 请求ID:reqId, 更新项: updates });
        return jsonResponse({
          success: true,
          message: `Updated ${updates.length} configuration item(s)`,
          updated: updates
        });
      }

      return jsonResponse({ error:{ message:"Method not allowed", type:"method_not_allowed"} }, 405);
    }

    /* 会话管理API - 需要管理员权限 */
    if (path==="/v1/admin/sessions"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }

      // GET: 查看会话（需要session_id参数）
      if (req.method==="GET"){
        const sessionId = url.searchParams.get("session_id");
        if (!sessionId) return badRequest("`session_id` query parameter is required.");

        const session = await sessionManager.getSession(sessionId);
        if (!session) return jsonResponse({ error:{ message:"Session not found" }}, 404);

        return jsonResponse({
          success: true,
          session: {
            sessionId: session.sessionId,
            messageCount: session.messages.length,
            kbList: session.kbList ?? [],
            hasKbList: !!(session.kbList && session.kbList.length > 0),
                            createdAt: new Date(session.createdAt).toISOString(),
                            lastAccessedAt: new Date(session.lastAccessedAt).toISOString(),
                            messages: session.messages.map(m => ({
                              role: m.role,
                              content: m.content.slice(0, 100) + (m.content.length > 100 ? "..." : ""),
                                                                 timestamp: new Date(m.timestamp).toISOString()
                            }))
          }
        });
      }

      // DELETE: 删除会话
      if (req.method==="DELETE"){
        const sessionId = url.searchParams.get("session_id");
        if (!sessionId) return badRequest("`session_id` query parameter is required.");

        await sessionManager.clearSession(sessionId);
        log.info({ 事件:"删除会话", 请求ID:reqId, sessionId });
        return jsonResponse({ success: true, message: "Session deleted successfully" });
      }

      return jsonResponse({ error:{ message:"Method not allowed", type:"method_not_allowed"} }, 405);
    }

    if (req.method==="GET" && path==="/v1/models"){
      // 仅服务端模式：使用下游token，不重试
      if (serverOnlyMode) {
        if (!downstreamToken) return unauthorized();

        const logCtx = { 请求ID:reqId, 上游: URL_MODELS, token: mask(downstreamToken), 模式: "仅服务端" };
        try{
          const resp = await fetchWithHeaderTimeout(URL_MODELS, {
            method:"GET",
            headers:{
              "Authorization": `Bearer ${downstreamToken}`,
              "Content-Type":"application/json",
              "X-Request-ID": reqId
            },
            headerTimeoutMs: HEADER_TIMEOUT_MS,
            logCtx
          });

          let raw = "";
          let data: any = {};
          try {
            raw = await withTimeout(resp.text(), BODY_TIMEOUT_MS, "upstream body timeout (models)", logCtx);
            log.debug({ 事件:"上游响应体(models原文)", 预览: raw.slice(0,700), 长度: raw.length, ...logCtx });
            try { data = JSON.parse(raw); } catch { data = raw; }
          } catch (e) {
            log.warn({ 事件:"上游读取超时(models)", 错误:String((e as any)?.message ?? e), ...logCtx });
            data = { error: { message: "upstream read timeout" } };
          }

          if (resp.status >= 200 && resp.status < 300) {
            let openaiFormat;
            if (data && Array.isArray(data.models)) {
              const now = Math.floor(Date.now() / 1000);
              openaiFormat = {
                object: "list",
                data: data.models.map((modelId: string) => ({
                  id: modelId,
                  object: "model",
                  created: now,
                  owned_by: "flowith"
                }))
              };
            } else if (data && data.object === "list") {
              openaiFormat = data;
            } else {
              openaiFormat = { object: "list", data: [] };
            }
            return jsonResponse(openaiFormat, resp.status);
          }

          return jsonResponse(typeof data==='string'? { error:{ message:data } } : data, resp.status);
        } catch (e) {
          return gatewayError(e);
        }
      }

      // 正常模式：使用token池和重试
      if (TOKENS.length === 0) return jsonResponse({ error:{ message:"No tokens configured" }}, 429);

      let attempt = 0, lastErr:any = null;
      while (attempt <= RETRY_MAX) {
        const picked = nextToken();
        if (!picked) break;
        const logCtx = { 请求ID:reqId, 上游: URL_MODELS, token: mask(picked.token) , 尝试: attempt+1 };

        try{
          const resp = await fetchWithHeaderTimeout(URL_MODELS, {
            method:"GET",
            headers:{
              "Authorization": `Bearer ${picked.token}`,
              "Content-Type":"application/json",
              "X-Request-ID": reqId
            },
            headerTimeoutMs: HEADER_TIMEOUT_MS,
            logCtx
          });

          let raw = "";
          let data: any = {};
          try {
            raw = await withTimeout(resp.text(), BODY_TIMEOUT_MS, "upstream body timeout (models)", logCtx);
            log.debug({ 事件:"上游响应体(models原文)", 预览: raw.slice(0,700), 长度: raw.length, ...logCtx });
            try { data = JSON.parse(raw); } catch { data = raw; }
          } catch (e) {
            log.warn({ 事件:"上游读取超时(models)", 错误:String((e as any)?.message ?? e), ...logCtx });
            data = { error: { message: "upstream read timeout" } };
          }

          if (resp.status >= 200 && resp.status < 300) {
            // 转换为标准 OpenAI 格式
            let openaiFormat;
            if (data && Array.isArray(data.models)) {
              const now = Math.floor(Date.now() / 1000);
              openaiFormat = {
                object: "list",
                data: data.models.map((modelId: string) => ({
                  id: modelId,
                  object: "model",
                  created: now,
                  owned_by: "flowith"
                }))
              };
              log.info({ 事件:"模型列表转换", 原始数量: data.count, 转换后数量: openaiFormat.data.length, ...logCtx });
            } else if (data && data.object === "list") {
              // 已经是 OpenAI 格式，直接返回
              openaiFormat = data;
            } else {
              // 未知格式，返回空列表
              log.warn({ 事件:"未知模型列表格式", 数据: data, ...logCtx });
              openaiFormat = {
                object: "list",
                data: []
              };
            }
            return jsonResponse(openaiFormat, resp.status);
          }

          log.warn({ 事件:"上游非2xx(models)", 状态: resp.status, 体预览: (typeof data==='string'?data:String(data)).slice(0,500), ...logCtx });
          if (!RETRY_ON_STATUS.has(resp.status) || attempt === RETRY_MAX) {
            return jsonResponse(typeof data==='string'? { error:{ message:data } } : data, resp.status);
          }
        } catch (e) {
          lastErr = e;
          log.warn({ 事件:"上游请求失败(models)", 错误:String((e as any)?.message ?? e), ...logCtx });
        }
        attempt++;
        if (RETRY_BACKOFF_BASE_MS>0) await delay(RETRY_BACKOFF_BASE_MS * attempt);
      }
      if (lastErr) return gatewayError(lastErr);
      return gatewayTimeout("REQUEST_TIMED_OUT");
    }
    if (req.method==="POST" && path==="/v1/chat/completions"){
      let body:any = {}; try { body = await req.json(); } catch { return badRequest("Invalid JSON body."); }
      const { model, messages, stream=false, kb_list, max_tokens, max_completion_tokens, session_id, tools, tool_choice, auto_session } = body ?? {};
      if (!Array.isArray(messages) || messages.length===0) return badRequest("`messages` is required and must be a non-empty array.");

      // 仅服务端模式检查
      if (serverOnlyMode && !downstreamToken) {
        return unauthorized();
      }

      if (!serverOnlyMode && TOKENS.length === 0) {
        return jsonResponse({ error:{ message:"No tokens configured" }}, 429);
      }

      // ============ 自动会话检测 ============
      // 如果启用 auto_session 或没有提供 session_id 但启用了长上下文，则自动生成会话 ID
      let effectiveSessionId = session_id;
      if (CONFIG.enableLongContext && (auto_session === true || (auto_session !== false && !session_id))) {
        // 生成基于 API key + 模型的自动会话 ID
        const apiKeyForSession = req.headers.get("authorization")?.slice(7) || req.headers.get("x-api-key") || "anonymous";
        const modelForSession = model || "default";
        effectiveSessionId = generateAutoSessionId(apiKeyForSession, modelForSession);
        log.info({ 事件:"自动会话", 会话ID: effectiveSessionId, 模型: modelForSession, ...{ 请求ID: reqId } });
      }

      let normMessages = normalizeMessages(messages);
      let finalKbList: string[];

      // ============ kb_list 处理（必须字段，UUID v4 数组） ============
      if (Array.isArray(kb_list) && kb_list.length > 0) {
        // 用户提供了 kb_list 数组
        finalKbList = kb_list.filter(id => typeof id === 'string' && id.trim()).map(id => id.trim());
        log.debug({ 事件:"使用提供的kb_list", kb_list: finalKbList, ...{ 请求ID: reqId } });
      } else if (CONFIG.enableLongContext && effectiveSessionId) {
        // 尝试从会话中获取
        const sessionKbList = await sessionManager.getKbList(effectiveSessionId);
        if (sessionKbList && sessionKbList.length > 0) {
          finalKbList = sessionKbList;
          log.info({ 事件:"复用会话kb_list", sessionId: effectiveSessionId, kb_list: finalKbList, ...{ 请求ID: reqId } });
        } else {
          // 会话中没有，生成新的 UUID v4 数组
          finalKbList = [crypto.randomUUID()];
          await sessionManager.setKbList(effectiveSessionId, finalKbList);
          log.info({ 事件:"生成新kb_list", sessionId: effectiveSessionId, kb_list: finalKbList, ...{ 请求ID: reqId } });
        }
      } else {
        // 没有会话，生成新的 UUID v4 数组
        finalKbList = [crypto.randomUUID()];
        log.info({ 事件:"生成新kb_list(无会话)", kb_list: finalKbList, ...{ 请求ID: reqId } });
      }

      // ============ 长上下文支持 ============
      if (CONFIG.enableLongContext && effectiveSessionId) {
        const contextMessages = await sessionManager.getContext(effectiveSessionId);
        if (contextMessages.length > 0) {
          // 合并历史上下文和当前消息
          normMessages = [...contextMessages, ...normMessages];
          log.info({ 事件:"加载会话上下文", sessionId: effectiveSessionId, 历史消息数: contextMessages.length, ...{ 请求ID: reqId } });
        }

        // 保存当前用户消息
        const userMessage = normMessages[normMessages.length - 1];
        if (userMessage) {
          await sessionManager.addMessage(effectiveSessionId, userMessage.role, userMessage.content, finalKbList);
        }
      }

      // ============ MCP工具准备 ============
      let mcpTools;
      
      if (tools && tools.length > 0) {
        // 用户明确提供了工具
        mcpTools = tools;
      } else if (CONFIG.enableCLIMode) {
        // CLI模式：自动注入所有CLI工具
        mcpTools = MCP_TOOLS.filter(t => CLI_TOOLS.includes(t.function.name));
        log.info({ 事件:"CLI模式启用", 工具数: mcpTools.length, ...{ 请求ID: reqId } });
      } else if (CONFIG.enableMCP) {
        // 普通MCP模式：根据配置注入工具
        if (CONFIG.mcpTools.length > 0) {
          mcpTools = MCP_TOOLS.filter(t => CONFIG.mcpTools.includes(t.function.name));
        } else if (tool_choice) {
          // 如果没有配置工具但指定了tool_choice，使用默认工具
          mcpTools = MCP_TOOLS.filter(t => COMMON_TOOLS.includes(t.function.name));
        }
      }

      // ============ 系统提示词注入 ============
      if (normMessages.length > 0) {
        const systemParts: string[] = [];
        
        // 1. 自定义系统提示词（最高优先级）
        if (CONFIG.systemPrompt) {
          systemParts.push(CONFIG.systemPrompt);
          log.debug({ 事件:"注入自定义系统提示词", 长度: CONFIG.systemPrompt.length, ...{ 请求ID: reqId } });
        }
        
        // 2. CLI模式提示词
        if (CONFIG.enableCLIMode) {
          systemParts.push(CONFIG.cliPrompt);
          log.debug({ 事件:"注入CLI模式提示词", 长度: CONFIG.cliPrompt.length, ...{ 请求ID: reqId } });
        }
        
        // 3. MCP工具提示词
        if (mcpTools && mcpTools.length > 0 && !CONFIG.enableCLIMode) {
          const toolNames = mcpTools.map((t: any) => t.function.name).join(", ");
          systemParts.push(`${CONFIG.mcpPrompt}\n\nAvailable tools: ${toolNames}`);
          log.debug({ 事件:"注入MCP工具提示词", 工具数: mcpTools.length, ...{ 请求ID: reqId } });
        }
        
        // 4. 思考提示词
        if (CONFIG.enableThinkingInjection) {
          systemParts.push(CONFIG.thinkingPrompt);
          log.debug({ 事件:"注入思考提示词", 长度: CONFIG.thinkingPrompt.length, ...{ 请求ID: reqId } });
        }
        
        // 合并所有系统提示词
        if (systemParts.length > 0) {
          const combinedSystemPrompt = systemParts.join("\n\n");
        const hasSystemMessage = normMessages.some(m => m.role === "system");

          if (!hasSystemMessage || CONFIG.enableSystemPromptOverride) {
            // 如果没有system消息，或者启用了覆盖模式，在最前面添加
            if (hasSystemMessage && CONFIG.enableSystemPromptOverride) {
              // 移除现有的system消息
              normMessages = normMessages.filter(m => m.role !== "system");
              log.debug({ 事件:"移除原有系统提示词(覆盖模式)", ...{ 请求ID: reqId } });
            }
          normMessages.unshift({
            role: "system",
              content: combinedSystemPrompt
          });
            log.info({ 事件:"系统提示词已注入(前置)", 字数: combinedSystemPrompt.length, ...{ 请求ID: reqId } });
        } else {
            // 如果已有system消息且未启用覆盖，追加到第一个system消息的内容后
          const firstSystemIdx = normMessages.findIndex(m => m.role === "system");
          if (firstSystemIdx !== -1) {
              normMessages[firstSystemIdx].content += "\n\n" + combinedSystemPrompt;
              log.info({ 事件:"系统提示词已注入(追加)", 字数: combinedSystemPrompt.length, ...{ 请求ID: reqId } });
            }
          }
        }
      }

      const isExternalStream = !!stream;
      const maxTok = Number.isFinite(max_completion_tokens) ? max_completion_tokens
      : Number.isFinite(max_tokens) ? max_tokens : undefined;

      const upstreamBody:any = {
        messages: normMessages,
        kb_list: finalKbList,  // 必须字段，UUID v4 数组
        stream: isExternalStream,
        ...(model? {model}:{}),
      ...(Number.isFinite(maxTok)? { max_tokens:maxTok }:{}),
      ...(mcpTools && mcpTools.length > 0 ? { tools: mcpTools } : {}),
      ...(tool_choice ? { tool_choice } : {})
      };

      const modelName = model ?? "flowith";

      log.info({
        事件:"聊天请求",
        ID: reqId,
        模型: modelName,
        消息数: normMessages.length,
        会话: effectiveSessionId ? `${effectiveSessionId.slice(0, 8)}...` : "无",
        工具: mcpTools?.length ?? 0,
        流式: isExternalStream
      });

      // ============ 仅服务端模式：不重试，直接透传 ============
      if (serverOnlyMode) {
        const logCtx = {
          请求ID:reqId,
          模型:modelName,
          token: mask(downstreamToken!),
      模式: "仅服务端"
        };

        try {
          const result = await callUpstreamChat({
            reqId,
            token: downstreamToken!,
            body: upstreamBody,
            forceStream: false,
              isExternalStream,
              modelName
          });

          if (result.kind === "stream") {
            // 直接透传流式响应
            stats.successRequests++;
            return new Response(result.resp.body, {
              headers: {
                "content-type": "text/event-stream; charset=utf-8",
                "cache-control": "no-cache, no-transform",
                "connection": "keep-alive",
                "x-request-id": reqId,
                "x-server-mode": "server-only"
              }
            });
          } else {
            const { status, content, headers } = result;

            if (status >= 200 && status < 300) {
              stats.successRequests++;
            } else {
              stats.failedRequests++;
            }

            let responseBody;
            try {
              responseBody = content ? JSON.parse(content) : openaiNonStream(modelName, content);
            } catch {
              responseBody = openaiNonStream(modelName, content);
            }

            return new Response(
              JSON.stringify(responseBody),
                                {
                                  status,
                                  headers: {
                                    "content-type": "application/json",
                                    "x-request-id": reqId,
                                    "x-server-mode": "server-only"
                                  }
                                }
            );
          }
        } catch (e) {
          stats.failedRequests++;
          log.error({ 事件: "仅服务端模式请求失败", 错误: String((e as any)?.message ?? e), ...logCtx });
          return gatewayError(e);
        }
      }

      // ============ 正常模式：使用token池和重试 ============
      let attempt = 0, lastErr:any=null, lastStatus=0, lastContent="", lastHeaders:Headers|null=null;
      let needsRetry = false;
      let lastTokenIdx = -1;
      let isTimeoutError = false; // 标记是否为超时错误

      while (attempt <= RETRY_MAX) {
        const picked = nextToken();
        if (!picked) break;

        const isKeySwitch = lastTokenIdx !== -1 && lastTokenIdx !== picked.idx;
        lastTokenIdx = picked.idx;

        const logCtx = {
          请求ID:reqId,
          模型:modelName,
          token: mask(picked.token),
      token索引: picked.idx,
      token总调用: picked.totalCalls,
      尝试:attempt+1,
      外部流:isExternalStream
        };

        if (attempt > 0) {
          log.info({
            事件:"上游请求准备(重试)",
                   使用token: `第${picked.idx + 1}个(共${TOKENS.length}个)`,
                   密钥切换: isKeySwitch ? "✓ 已切换" : "未切换",
                   ...logCtx
          });
        } else {
          log.info({
            事件:"上游请求准备",
            使用token: `第${picked.idx + 1}个(共${TOKENS.length}个)`,
                   ...logCtx
          });
        }

        needsRetry = false;
        isTimeoutError = false;

        try{
          const result = await callUpstreamChat({
            reqId, token:picked.token, body: upstreamBody,
            forceStream: false, isExternalStream, modelName
          });
          if (result.kind === "stream") {
            let idleTimer: number | undefined;
            let totalTimer: number | undefined;
            let readerClosed = false;
            const upstreamResp = result.resp;

            const readable = new ReadableStream({
              async start(controller){
                const body = upstreamResp.body as ReadableStream<Uint8Array> | null;
                if (!body) {
                  const doneObj = { id:"done", object:"chat.completion.chunk",
                    choices:[{ index:0, delta:{}, finish_reason:"stop"}],
                    created: Math.floor(Date.now()/1000), model: modelName };
                    controller.enqueue(enc.encode(`data: ${JSON.stringify(doneObj)}\n\n`));
                    controller.enqueue(enc.encode(`data: [DONE]\n\n`));
                    controller.close(); return;
                }
                const reader = body.getReader();
                let buf = "";
                let thinkingBuffer = "";  // 用于拼凑思考内容
                let isInThinking = false;  // 是否正在收集thinking
                let hasOutputThinkingHeader = false;  // 是否已输出思考头部

                const safeClose = () => {
                  if (readerClosed) return;
                  readerClosed = true;
                  // 如果还有未输出的thinking，先输出
                  if (thinkingBuffer.trim()) {
                    const thinkChunk = openaiChunk(modelName, `\n\n--- Response ---\n\n`);
                    controller.enqueue(enc.encode(`data: ${JSON.stringify(thinkChunk)}\n\n`));
                  }
                  const doneObj = { id:"done", object:"chat.completion.chunk",
                    choices:[{ index:0, delta:{}, finish_reason:"stop"}],
                    created: Math.floor(Date.now()/1000), model: modelName };
                    controller.enqueue(enc.encode(`data: ${JSON.stringify(doneObj)}\n\n`));
                    controller.enqueue(enc.encode(`data: [DONE]\n\n`));
                    try { controller.close(); } catch {}
                    if (idleTimer)  clearTimeout(idleTimer);
                    if (totalTimer) clearTimeout(totalTimer);
                };
                  const resetIdle = () => {
                    if (idleTimer) clearTimeout(idleTimer);
                    idleTimer = setTimeout(() => {
                      log.warn({ 事件:"上游SSE空闲超时", ...logCtx, 空闲毫秒: STREAM_IDLE_TIMEOUT_MS });
                      try { reader.cancel("idle timeout"); } catch {}
                      safeClose();
                    }, STREAM_IDLE_TIMEOUT_MS) as unknown as number;
                  };
                  const startTotal = () => {
                    totalTimer = setTimeout(() => {
                      log.warn({ 事件:"上游SSE总时限触发", ...logCtx, 总毫秒: STREAM_TOTAL_TIMEOUT_MS });
                      try { reader.cancel("total timeout"); } catch {}
                      safeClose();
                    }, STREAM_TOTAL_TIMEOUT_MS) as unknown as number;
                  };

                  resetIdle();
                  startTotal();

                  try{
                    while (true){
                      const { done, value } = await reader.read();
                      if (done) break;
                      resetIdle();
                      buf += dec.decode(value, { stream:true });

                      // 处理多种分隔符：\n\n（SSE标准）、\n（text/plain）、}\n（JSON流）
                      let processedAny = false;

                      // 优先处理 \n\n 分隔（SSE标准格式）
                      let idx;
                      while ((idx = buf.indexOf("\n\n")) !== -1){
                        processedAny = true;
                        const evt = buf.slice(0, idx); buf = buf.slice(idx+2);

                        // 尝试解析SSE格式
                        const dataLines = evt.split("\n")
                        .map(l => l.trimEnd())
                        .filter(l => l.startsWith("data:"))
                        .map(l => l.slice(5).trim());

                        const data = dataLines.length > 0 ? dataLines.join("\n") : evt.trim();
                        if (!data) continue;

                        log.debug({ 事件:"上游流分片", 原文预览: data.slice(0,200), ...logCtx });

                        // 检查是否为 [DONE] 标记
                        if (data === "[DONE]") {
                          log.debug({ 事件:"流式收到[DONE]标记", ...logCtx });
                          safeClose();
                          return;
                        }

                        try{
                          const obj = JSON.parse(data);
                          // Flowith格式处理
                          if (obj?.tag === "seeds") {
                            log.debug({ 事件:"流式收到seeds标记", 内容: obj.content, ...logCtx });
                            continue;
                          }

                          if (obj?.tag === "final") {
                            const delta = typeof obj?.content === "string" ? obj.content : String(obj.content ?? "");
                            if (delta === "[DONE]") {
                              log.debug({ 事件:"流式收到final+[DONE]标记", ...logCtx });
                              safeClose();
                              return;
                            }

                            // 检测是否为thinking内容（仅当启用时）
                            const isThinking = CONFIG.enableThinkingTags &&
                            (obj?.type === "thinking" || delta.includes("<think>") || delta.includes("</think>") ||
                             delta.includes(CONFIG.thinkingStartTag) || delta.includes(CONFIG.thinkingEndTag));

                            if (CONFIG.enableThinkingTags && (isThinking || isInThinking)) {
                              isInThinking = true;
                              thinkingBuffer += delta;

                              // 输出thinking头部（只输出一次）
                              if (!hasOutputThinkingHeader) {
                                hasOutputThinkingHeader = true;
                                let headerText = "";
                                if (CONFIG.thinkingTagFormat === "markdown") {
                                  headerText = "\n\n**Thinking:**\n\n";
                                } else if (CONFIG.thinkingTagFormat === "custom") {
                                  headerText = `\n${CONFIG.thinkingStartTag}\n`;
                                } else {
                                  headerText = `\n<thinking>\n`;
                                }
                                const headerChunk = openaiChunk(modelName, headerText);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(headerChunk)}\n\n`));
                              }

                              // 立即输出thinking内容（不等待完整）
                              if (delta) {
                                const thinkChunk = openaiChunk(modelName, delta);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(thinkChunk)}\n\n`));
                              }

                              // 检测thinking结束
                              const isThinkingEnd = delta.includes("</think>") || obj?.thinking_complete ||
                                                   delta.includes(CONFIG.thinkingEndTag);
                              if (isThinkingEnd) {
                                isInThinking = false;
                                let endText = "";
                                if (CONFIG.thinkingTagFormat === "markdown") {
                                  endText = "\n\n**Response:**\n\n";
                                } else if (CONFIG.thinkingTagFormat === "custom") {
                                  endText = `\n${CONFIG.thinkingEndTag}\n\n`;
                                } else {
                                  endText = `\n</thinking>\n\n`;
                                }
                                const endChunk = openaiChunk(modelName, endText);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(endChunk)}\n\n`));
                              }
                            } else {
                              // 正常内容
                              if (delta) {
                                // 性能优化：复用chunk对象
                                if (CONFIG.enableStreamOptimization) {
                                  controller.enqueue(enc.encode(`data: ${JSON.stringify(openaiChunk(modelName, delta))}\n\n`));
                                } else {
                                  const chunk = openaiChunk(modelName, delta);
                                  controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                                }
                              }
                            }
                          } else {
                            // 其他格式兼容
                            const delta = typeof obj?.content === "string" ? obj.content : "";
                            if (delta) {
                              const chunk = openaiChunk(modelName, delta);
                              controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                            }
                          }
                        }catch{
                          // JSON解析失败，尝试作为纯文本处理
                          const { delta, isFinal } = extractDeltaFromTextChunk(data);
                          if (delta && delta !== "[DONE]") {
                            const chunk = openaiChunk(modelName, delta);
                            controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                          }
                          if (isFinal || delta === "[DONE]") { safeClose(); return; }
                        }
                      }

                      // 如果没有处理 \n\n 分隔符，尝试处理单个 \n（纯文本流）
                      if (!processedAny && buf.includes("\n")) {
                        const lines = buf.split("\n");
                        buf = lines.pop() || "";  // 保留最后一行（可能不完整）

                        for (const line of lines) {
                          const trimmed = line.trim();
                          if (!trimmed) continue;

                          // 尝试解析JSON
                          try {
                            const obj = JSON.parse(trimmed);
                            if (obj?.content) {
                              const chunk = openaiChunk(modelName, obj.content);
                              controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                            }
                          } catch {
                            // 作为纯文本处理
                            if (trimmed && trimmed !== "[DONE]") {
                              const chunk = openaiChunk(modelName, trimmed);
                              controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                            }
                          }
                        }
                      }
                    }
                  } catch (e) {
                    log.warn({ 事件:"上游流读取异常", 错误:String((e as any)?.message ?? e), ...logCtx });
                  } finally {
                    safeClose();
                  }
              }
            });

            stats.successRequests++;
            await saveStatsToStorage(); // 流式成功时保存统计
            return new Response(readable, {
              headers:{
                "content-type":"text/event-stream; charset=utf-8",
                "cache-control":"no-cache, no-transform",
                "connection":"keep-alive",
                "x-request-id": reqId
              }
            });
          } else {
            const { status, content, headers, isEmpty, isTruncated } = result;

            // 检查是否需要重试
            let shouldRetry = false;
            let retryReason = "";

            // 1. 检查 SSE 空返回或截断
            if ((isEmpty || isTruncated) && SSE_RETRY_ON_EMPTY && attempt < RETRY_MAX) {
              shouldRetry = true;
              retryReason = isEmpty ? "返回为空" : "数据截断";
            }

            // 2. 检查上游错误状态码（如果配置了可重试的状态码）
            if (!shouldRetry && status >= 400 && RETRY_ON_STATUS.has(status) && attempt < RETRY_MAX) {
              shouldRetry = true;
              retryReason = `上游返回错误状态 ${status}`;
            }

            if (shouldRetry) {
              log.warn({
                事件:"准备重试",
                原因: retryReason,
                状态: status,
                字数: content.length,
                当前尝试: attempt + 1,
                最大尝试: RETRY_MAX + 1,
                下次将切换密钥: TOKENS.length > 1 ? "是(负载均衡)" : "否(仅1个key)",
                       ...logCtx
              });
              needsRetry = true;
              lastContent = content;
              lastStatus = status;
              lastHeaders = headers;
            } else {
              // 不需要重试或已达到最大重试次数
              log.info({
                事件:"下游返回(OpenAI非流式)",
                       状态: status,
                       字数: content.length,
                       是否为空: isEmpty,
                       是否截断: isTruncated,
                       是否重试过: attempt > 0,
                       总尝试次数: attempt + 1,
                       ...logCtx
              });

              if (status >= 200 && status < 300 && !isEmpty) {
                stats.successRequests++;
                await saveStatsToStorage(); // 成功时保存统计

                // 保存助手回复到会话
                if (CONFIG.enableLongContext && effectiveSessionId && content) {
                  await sessionManager.addMessage(effectiveSessionId, "assistant", content);
                  log.debug({ 事件:"保存助手回复", sessionId: effectiveSessionId, 字数: content.length, 自动会话: effectiveSessionId && !session_id, ...{ 请求ID: reqId } });
                }
              } else {
                stats.failedRequests++;
                await saveStatsToStorage();
              }

              // 透传上游的错误状态和内容
              let responseBody;
              try {
                // 尝试解析为 JSON（上游可能返回结构化错误）
                responseBody = content ? JSON.parse(content) : openaiNonStream(modelName, content);
              } catch {
                // 解析失败，包装为标准格式
                responseBody = openaiNonStream(modelName, content);
              }

              return new Response(
                JSON.stringify(responseBody),
                                  { status, headers: {
                                    "content-type":"application/json",
                                    "x-request-id": reqId,
                                    "x-retry-attempts": String(attempt + 1)
                                  }}
              );
            }
          }
        } catch (e) {
          lastErr = e;
          const errorMsg = String((e as any)?.message ?? e);
          
          // 检查是否为超时错误
          isTimeoutError = errorMsg.includes("timeout") || errorMsg.includes("Timeout") || 
                          errorMsg.includes("TIMEOUT") || errorMsg.includes("timed out");
          
          // 如果是超时错误且配置了不重试，则直接退出
          if (isTimeoutError && CONFIG.noRetryOnTimeout) {
            log.error({
              事件:"超时错误(不重试)",
              错误: errorMsg,
              配置: "NO_RETRY_ON_TIMEOUT=true",
              尝试: attempt + 1,
              ...{ 请求ID:reqId }
            });
            needsRetry = false;
            break; // 直接退出循环
          }
          
          needsRetry = true;
          log.warn({
            事件:"上游调用异常(重试点)",
                   错误: errorMsg,
                   是否超时: isTimeoutError,
                   堆栈: (e as any)?.stack?.split('\n').slice(0, 3).join(' '),
                   尝试:attempt+1,
                   下次将切换密钥: TOKENS.length > 1 && attempt < RETRY_MAX ? "是(负载均衡)" : "否",
                   ...{ 请求ID:reqId }
          });
        }

        // 检查是否需要继续重试
        if (!needsRetry) break;

        attempt++;
        if (attempt > RETRY_MAX) break;

        // 预测下一个将使用的密钥（用于日志显示）
        const nextKeyIdx = Atomics.load(rrView, 0) % TOKENS.length;
        const nextKeyPreview = TOKENS.length > 0 ? `第${nextKeyIdx + 1}个(${mask(TOKENS[nextKeyIdx])})` : "无";

        const backoffMs = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1); // 指数退避
        log.info({
          事件:"重试退避",
          延迟毫秒: backoffMs,
          下次尝试: attempt+1,
          下次密钥: TOKENS.length > 1 ? nextKeyPreview : "无切换",
          ...{ 请求ID:reqId }
        });
        if (backoffMs > 0) await delay(backoffMs);
      }

      stats.failedRequests++;
      await saveStatsToStorage(); // 失败时也保存统计

      // 透传最后的错误状态和信息
      log.error({
        事件:"所有重试失败",
        总尝试次数: attempt + 1,
        最后状态: lastStatus,
        最后错误: lastErr ? String((lastErr as any)?.message ?? lastErr) : "无",
                内容长度: lastContent?.length ?? 0,
                请求ID: reqId
      });

      if (lastErr) {
        return gatewayError(lastErr);
      }

      if (lastStatus && lastContent) {
        // 尝试透传上游的原始错误响应
        let errorBody;
        try {
          errorBody = JSON.parse(lastContent);
        } catch {
          // 解析失败，包装为标准错误格式
          errorBody = {
            error: {
              message: lastContent.slice(0, 500),
      type: "upstream_error",
      status: lastStatus
            }
          };
        }

        return new Response(
          JSON.stringify(errorBody),
                            {
                              status: lastStatus,
                              headers: {
                                "content-type": "application/json",
                                "x-request-id": reqId,
                                "x-retry-attempts": String(attempt + 1),
                            "x-all-retries-failed": "true"
                              }
                            }
        );
      }

      if (lastStatus) {
        return jsonResponse({
          error:{
            message: `HTTP ${lastStatus}`,
            type: "upstream_error",
            status: lastStatus
          }
        }, lastStatus, {
          "x-request-id": reqId,
          "x-retry-attempts": String(attempt + 1),
                            "x-all-retries-failed": "true"
        });
      }

      return gatewayTimeout("REQUEST_TIMED_OUT");
    }

    // Claude API 兼容端点：/v1/messages
    if (req.method==="POST" && path==="/v1/messages" && CONFIG.enableClaudeAPI){
      const requestStartTime = Date.now();
      let claudeBody:any = {};
      try { claudeBody = await req.json(); } catch { return badRequest("Invalid JSON body."); }

      const { model, messages, system, max_tokens, stream: claudeStream, temperature, top_p } = claudeBody ?? {};
      if (!Array.isArray(messages) || messages.length===0) {
        return badRequest("`messages` is required and must be a non-empty array.");
      }

      // 仅服务端模式检查
      if (serverOnlyMode && !downstreamToken) {
        return unauthorized();
      }

      if (!serverOnlyMode && TOKENS.length === 0) {
        return jsonResponse({ error:{ message:"No tokens configured" }}, 429);
      }

      // 转换为 OpenAI 格式
      const convertedMessages = normalizeMessages(messages);
      const finalMessages = system && typeof system === "string"
      ? [{ role: "system", content: system }, ...convertedMessages]
      : convertedMessages;

      // 构造转发请求到 /v1/chat/completions
      const openaiBody = {
            model: model ?? "claude-3-5-sonnet",
            messages: finalMessages,
        stream: claudeStream ?? false,
        max_tokens: max_tokens,
        temperature,
        top_p
      };

      log.info({
        事件: "Claude API请求",
        ID: reqId,
        模型: openaiBody.model,
        消息数: finalMessages.length,
        流式: openaiBody.stream
      });

      // 内部转发到 chat/completions 处理逻辑
      // 重用现有的处理逻辑
      const normMessages = finalMessages;
      const finalKbList: string[] = [crypto.randomUUID()];
      const isExternalStream = !!openaiBody.stream;
      const modelName = openaiBody.model;

      const upstreamBody:any = {
        messages: normMessages,
        kb_list: finalKbList,
        stream: isExternalStream,
        model: modelName,
        ...(openaiBody.max_tokens ? { max_tokens: openaiBody.max_tokens } : {})
      };

      // 简化处理：仅使用第一个token或下游token
      const picked = serverOnlyMode ? null : nextToken();
      const useToken = serverOnlyMode ? downstreamToken! : (picked ? picked.token : null);

      if (!useToken) {
        return jsonResponse({ error:{ message:"No tokens available" }}, 503);
      }

      try {
        const result = await callUpstreamChat({
          reqId,
          token: useToken,
          body: upstreamBody,
          forceStream: false,
          isExternalStream,
          modelName
        });

        const elapsed = Date.now() - requestStartTime;
        recordResponseTime(elapsed);

        if (result.kind === "stream") {
          stats.successRequests++;
          return new Response(result.resp.body, {
            headers: {
              "content-type": "text/event-stream; charset=utf-8",
              "cache-control": "no-cache, no-transform",
              "connection": "keep-alive",
              "x-request-id": reqId,
              "anthropic-version": "2023-06-01"
            }
          });
        } else {
          const { status, content } = result;

          if (status >= 200 && status < 300) {
            stats.successRequests++;
            // 转换为 Claude 格式响应
            return jsonResponse({
              id: "msg_" + crypto.randomUUID().replace(/-/g, ''),
              type: "message",
              role: "assistant",
              content: [{ type: "text", text: content }],
              model: modelName,
              stop_reason: "end_turn",
              usage: {
                input_tokens: 0,
                output_tokens: 0
              }
            }, status, {
              "x-request-id": reqId,
              "anthropic-version": "2023-06-01"
            });
          } else {
            stats.failedRequests++;
            return jsonResponse({ error:{ message: content || "Upstream error", type:"api_error" }}, status);
          }
        }
      } catch (e) {
        stats.failedRequests++;
        const elapsed = Date.now() - requestStartTime;
        recordResponseTime(elapsed);
        log.error({ 事件: "Claude API请求失败", ID: reqId, 错误: String((e as any)?.message ?? e), 耗时ms: elapsed });
        return gatewayError(e);
      }
    }

    stats.failedRequests++;
    return jsonResponse({ error:{ message:"Not Found", type:"not_found"} }, 404);
  } catch (e){
    stats.failedRequests++;
    log.error({ 事件:"处理异常", 错误:String((e as any)?.message ?? e), 堆栈: (e as any)?.stack, 请求ID:reqId });
    return gatewayError(e);
  }
}, { port: PORT });

const rsyncMode = getEnv("RSYNC", "0").trim() === "1";
log.info({
  事件:"服务启动",
  端口: PORT,
  ORIGIN,
  TOKENS数量: TOKENS.length,
  TOKENS预览: TOKENS.slice(0, 3).map(mask),
         存储类型: STORAGE_TYPE,
         存储状态: storage !== null ? "已启用" : "未启用",
         同步模式: rsyncMode ? "完全同步(RSYNC=1)" : "差异同步",
         功能: {
           长上下文: CONFIG.enableLongContext,
           思考注入: CONFIG.enableThinkingInjection,
           MCP工具: CONFIG.enableMCP,
           CLI模式: CONFIG.enableCLIMode,
           CLI工具数: CONFIG.enableCLIMode ? CLI_TOOLS.length : 0,
           仅服务端模式: CONFIG.serverOnly,
           Claude_API: CONFIG.enableClaudeAPI
         }
});
