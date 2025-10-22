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
  
  constructor(path: string) {
    this.db = new DB(path);
    this.db.execute(`
      CREATE TABLE IF NOT EXISTS kv_store (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expire_at INTEGER
      )
    `);
    this.db.execute(`CREATE INDEX IF NOT EXISTS idx_expire ON kv_store(expire_at)`);
    // 定期清理过期数据
    setInterval(() => this.cleanup(), 60000);
  }
  
  private cleanup() {
    try {
      const now = Date.now();
      this.db.query("DELETE FROM kv_store WHERE expire_at IS NOT NULL AND expire_at < ?", [now]);
  } catch (e) {
      console.error("[SQLite] Cleanup error:", e);
    }
  }
  
  async get<T>(key: string[]): Promise<T | null> {
    const keyStr = JSON.stringify(key);
    const now = Date.now();
    const rows = this.db.query("SELECT value FROM kv_store WHERE key = ? AND (expire_at IS NULL OR expire_at > ?)", [keyStr, now]);
    
    if (rows.length === 0) return null;
    
    try {
      return JSON.parse(rows[0][0] as string) as T;
    } catch {
      return null;
    }
  }
  
  async set<T>(key: string[], value: T, options?: { expireIn?: number }): Promise<void> {
    const keyStr = JSON.stringify(key);
    const valueStr = JSON.stringify(value);
    const expireAt = options?.expireIn ? Date.now() + options.expireIn : null;
    
    this.db.query(
      "INSERT OR REPLACE INTO kv_store (key, value, expire_at) VALUES (?, ?, ?)",
      [keyStr, valueStr, expireAt]
    );
  }
  
  async delete(key: string[]): Promise<void> {
    const keyStr = JSON.stringify(key);
    this.db.query("DELETE FROM kv_store WHERE key = ?", [keyStr]);
  }
  
  async close(): Promise<void> {
    this.db.close();
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

// ============ 存储初始化 ============
const STORAGE_TYPE = (Deno.env.get("STORAGE_TYPE") ?? "kv").toLowerCase();
let storage: StorageAdapter | null = null;
let kv: Deno.Kv | null = null; // 保留向后兼容

async function initStorage(): Promise<void> {
  const kvPath = Deno.env.get("DENO_KV_PATH");
  const sqlitePath = Deno.env.get("SQLITE_PATH") || "./data.db";
  
  try {
    if (STORAGE_TYPE === "sqlite") {
      storage = new SQLiteAdapter(sqlitePath);
      console.log(`[Storage] SQLite initialized at ${sqlitePath}`);
    } else if (STORAGE_TYPE === "memory") {
      storage = new MemoryAdapter();
      console.log("[Storage] Memory storage initialized");
    } else {
      // 默认使用 Deno KV
      const denoKv = await Deno.openKv(kvPath);
      kv = denoKv; // 保留向后兼容
      storage = new DenoKVAdapter(denoKv);
      console.log(`[Storage] Deno KV initialized${kvPath ? ` at ${kvPath}` : ""}`);
    }
  } catch (e) {
    console.error("[Storage] Initialization failed:", e);
    console.log("[Storage] Falling back to memory storage");
    storage = new MemoryAdapter();
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
  // 长上下文配置
  enableLongContext: boolean;
  maxContextMessages: number;
  contextTTLSeconds: number;
  // 思考注入配置
  enableThinkingInjection: boolean;
  thinkingPrompt: string;
  // MCP配置
  enableMCP: boolean;
  mcpTools: string[];
  // 存储配置
  storageType: "kv" | "sqlite" | "memory";
  sqlitePath?: string;
  // 仅服务端模式
  serverOnly: boolean;
  // Claude API 兼容
  enableClaudeAPI: boolean;
  // 思考功能增强
  enableThinkingTags: boolean;
  // 性能优化
  enableStreamOptimization: boolean;
}

// 从环境变量加载配置
function loadConfigFromEnv(): AppConfig {
  const flowithBase = (Deno.env.get("FLOWITH_BASE") ?? "").trim();
  const flowithRegion = (Deno.env.get("FLOWITH_REGION") ?? "").trim();
  const origin = flowithBase
    ? flowithBase.replace(/\/+$/, "")
    : (flowithRegion ? `https://${flowithRegion}.edge.flowith.net` : `https://edge.flowith.net`);

  const storageTypeEnv = (Deno.env.get("STORAGE_TYPE") ?? "kv").toLowerCase();
  const storageType = (storageTypeEnv === "sqlite" || storageTypeEnv === "memory") ? storageTypeEnv : "kv";

  return {
    // tokens 不从这里加载,而是通过 syncTokensFromEnv() 统一管理
    tokens: [],
    apiKeys: (Deno.env.get("API_KEYS") ?? "").split(",").map(s => s.trim()).filter(Boolean),
    adminKey: (Deno.env.get("ADMIN_KEY") ?? Deno.env.get("API_KEYS") ?? "").split(",")[0]?.trim() ?? "",
    port: Number(Deno.env.get("PORT") ?? "8787"),
    logLevel: (Deno.env.get("LOG_LEVEL") ?? "info").toLowerCase(),
    flowithBase,
    flowithRegion,
    origin,
    headerTimeoutMs: Math.max(1000, Number(Deno.env.get("UPSTREAM_TIMEOUT_MS") ?? "25000")),
    bodyTimeoutMs: Math.max(2000, Number(Deno.env.get("UPSTREAM_BODY_TIMEOUT_MS") ?? "30000")),
    streamIdleTimeoutMs: Math.max(2000, Number(Deno.env.get("STREAM_IDLE_TIMEOUT_MS") ?? "15000")),
    streamTotalTimeoutMs: Math.max(5000, Number(Deno.env.get("STREAM_TOTAL_TIMEOUT_MS") ?? "180000")),
    retryMax: Math.max(0, Number(Deno.env.get("UPSTREAM_RETRY_MAX") ?? "3")),
    retryBackoffBaseMs: Math.max(0, Number(Deno.env.get("UPSTREAM_RETRY_BACKOFF_MS") ?? "200")),
    sseRetryOnEmpty: (Deno.env.get("SSE_RETRY_ON_EMPTY") ?? "true").toLowerCase() === "true",
    sseMinContentLength: Math.max(0, Number(Deno.env.get("SSE_MIN_CONTENT_LENGTH") ?? "10")),
    retryOnStatus: [401, 403, 408, 402, 409, 425, 429, 500, 502, 503, 504],
    enableLongContext: (Deno.env.get("ENABLE_LONG_CONTEXT") ?? "true").toLowerCase() === "true",
    maxContextMessages: Math.max(1, Number(Deno.env.get("MAX_CONTEXT_MESSAGES") ?? "20")),
    contextTTLSeconds: Math.max(60, Number(Deno.env.get("CONTEXT_TTL_SECONDS") ?? "3600")),
    enableThinkingInjection: (Deno.env.get("ENABLE_THINKING_INJECTION") ?? "true").toLowerCase() === "true",
    thinkingPrompt: Deno.env.get("THINKING_PROMPT") ?? "Please think step by step before answering.",
    enableMCP: (Deno.env.get("ENABLE_MCP") ?? "true").toLowerCase() === "true",
    mcpTools: (Deno.env.get("MCP_TOOLS") ?? "web_search,image_gen,code_interpreter").split(",").map(s => s.trim()).filter(Boolean),
    storageType: storageType as "kv" | "sqlite" | "memory",
    sqlitePath: Deno.env.get("SQLITE_PATH") || "./data.db",
    serverOnly: (Deno.env.get("SERVER_ONLY") ?? "false").toLowerCase() === "true",
    enableClaudeAPI: (Deno.env.get("ENABLE_CLAUDE_API") ?? "true").toLowerCase() === "true",
    enableThinkingTags: (Deno.env.get("ENABLE_THINKING_TAGS") ?? "true").toLowerCase() === "true",
    enableStreamOptimization: (Deno.env.get("ENABLE_STREAM_OPTIMIZATION") ?? "true").toLowerCase() === "true"
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

// 兼容性:从配置对象读取值
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
  lastResetTime: Date.now()
};

interface Session {
  sessionId: string;
  messages: Array<{ role: string; content: string; timestamp: number }>;
  createdAt: number;
  lastAccessedAt: number;
  kbList?: string[];  // 保存 kb_list UUID v4 数组,连续对话时复用
  metadata?: Record<string, any>;
  apiKey?: string;    // 关联的 API key(用于自动会话)
  model?: string;     // 关联的模型(用于自动会话)
}

// 生成自动会话 ID(基于 API key + 模型)
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

    // 更新或设置 kb_list(如果提供)
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

// 定期清理过期会话(每5分钟)
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
  }
];

// 加载初始数据
if (storage) {
  await loadConfigFromStorage();  // 先加载配置
  await loadTokensFromStorage();  // 从存储加载已保存的tokens
  await syncTokensFromEnv(); // 同步环境变量中的tokens(差异或完全同步)
  await loadStatsFromStorage();
  await saveConfigToStorage();  // 保存当前配置(如果存储中没有)
} else {
  // 如果没有存储,也执行环境变量同步(只是不保存)
  const envTokensStr = Deno.env.get("FLOWITH_AUTH_TOKENS") ?? "";
  const envTokens = Array.from(new Set(
    envTokensStr.split(",").map(s => s.trim()).filter(Boolean)
  ));
  if (envTokens.length > 0 && TOKENS.length === 0) {
    TOKENS.push(...envTokens);
    console.log(`[Sync] Loaded ${TOKENS.length} tokens from environment (no storage)`);
  }
}

// 定期保存统计数据(每30秒)
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

// 初始化轮询索引(从0开始)
Atomics.store(rrView, 0, 0);

/**
 * 获取下一个token(按顺序轮询)
 * 实现方式:使用原子操作确保并发安全
 * 第1次请求 -> token[0]
 * 第2次请求 -> token[1]
 * 第3次请求 -> token[2]
 * ...
 * 第N+1次请求 -> token[0](循环)
 */
function nextToken(): { idx:number, token:string, totalCalls: number } | null {
  const n = TOKENS.length;
  if (n === 0) {
    log.warn({ 事件:"无可用token", 时间: new Date().toISOString() });
    return null;
  }
  
  // 原子操作:获取当前索引并自增
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
 * 获取当前轮询状态(不移动索引)
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
  
  // 优先使用 ADMIN_KEY,如果没有则使用 API_KEYS
  if (ADMIN_KEY) {
    return provided === ADMIN_KEY;
  }
  
  // 如果没有 ADMIN_KEY,则检查 API_KEYS(任何一个 API_KEY 都可以作为管理员)
  if (API_KEYS.length > 0) {
    return API_KEYS.includes(provided);
  }
  
  return false; // 没有配置任何密钥
}
async function addToken(token:string): Promise<{ success:boolean, message:string }> {
  const trimmed = token.trim();
  if (!trimmed) return { success:false, message:"Token cannot be empty" };
  if (TOKENS.includes(trimmed)) return { success:false, message:"Token already exists" };
  TOKENS.push(trimmed);
  await saveTokensToStorage();
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
    if (TOKENS.includes(trimmed)) {
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
      // 如果保存失败,回滚已添加的tokens
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
  const envTokensStr = Deno.env.get("FLOWITH_AUTH_TOKENS") ?? "";
  const envTokens = Array.from(new Set(
    envTokensStr.split(",").map(s => s.trim()).filter(Boolean)
  ));
  
  const rsyncMode = (Deno.env.get("RSYNC") ?? "0").trim() === "1";
  
  if (envTokens.length === 0) {
    console.log("[Sync] No tokens in environment variable, skipping sync");
    return;
  }
  
  if (rsyncMode) {
    // 完全同步模式:清空存储,完全替换
    console.log(`[Sync] RSYNC mode enabled: clearing all tokens and loading ${envTokens.length} tokens from environment`);
    TOKENS.length = 0;
    TOKENS.push(...envTokens);
    await saveTokensToStorage();
    console.log(`[Sync] Full sync completed: ${TOKENS.length} tokens loaded`);
  } else {
    // 差异同步模式:只添加新的token,保留存储中已有的
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
  try{
    const hdrs = new Headers(rest.headers as HeadersInit);
    const hdrEntries = Object.fromEntries(hdrs.entries());
    if (hdrEntries["authorization"]) hdrEntries["authorization"] = `Bearer ${mask((hdrEntries["authorization"] as string).slice(7))}`;
    log.info({ 事件:"上游请求", 方法:(rest.method ?? "GET"), URL: typeof input==="string"? input : (input as Request).url, 头: hdrEntries, ...logCtx });
    const resp = await fetch(input, { ...rest, signal: controller.signal });
    clearTimeout(timer);
    log.info({
      事件:"上游响应头",
      状态: resp.status,
      类型: resp.headers.get("content-type") ?? "",
             长度: resp.headers.get("content-length") ?? "",
             头: Object.fromEntries(resp.headers.entries()),
             ...logCtx
    });
    return resp;
  }catch(e){
    clearTimeout(timer);
    log.warn({ 事件:"上游请求异常/首包超时", 错误:String((e as any)?.message ?? e), ...logCtx });
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
function openaiChunk(model:string, textDelta:string){
  return { id: "chatcmpl_" + Math.random().toString(36).slice(2), object:"chat.completion.chunk",
    created: Math.floor(Date.now()/1000), model,
    choices:[{ index:0, delta:{ content:textDelta }, finish_reason:null }] };
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

        // 检查是否为 [DONE] 标记(非JSON格式)
        if (data === "[DONE]") {
          log.debug({ 事件:"收到[DONE]标记", ...logCtx });
          readerClosed = true;
          break;
        }

        try {
          const obj = JSON.parse(data);
          // Flowith格式:每个chunk都有tag:final,只有content为"[DONE]"时才真正结束
          if (obj?.tag === "seeds") {
            // seeds标记,跳过
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
            // 正常内容,累加
          if (delta) content += delta;
          } else {
            // 其他格式兼容
            const delta = typeof obj?.content === "string" ? obj.content : "";
            if (delta) content += delta;
          }
        } catch {
          // JSON解析失败,尝试提取文本
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

  // 对于外部流式请求,无论上游返回什么content-type都需要转换为标准SSE格式
  // 因为上游可能返回 text/plain,需要统一处理
  if (isExternalStream && upstreamStream) {
    // 不再直接透传,而是进行格式转换
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
  
  // 仅服务端模式:跳过API_KEYS鉴权,直接透传下游的Authorization
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
    // 正常模式:需要鉴权(支持Bearer和x-api-key两种格式)
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
  const preview = (req.method === "POST" || req.method === "PUT" || req.method === "PATCH")
  ? await req.clone().text().catch(()=> "")
  : "";
  log.info({
    事件:"入站请求",
    请求ID:reqId,
    方法:req.method,
    路径:path,
    UA: req.headers.get("user-agent") ?? "",
           请求体长度: preview.length,
           请求体预览: preview.slice(0, 400),
           当前tokens数: TOKENS.length
  });

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
                            sse_min_content_length: CONFIG.sseMinContentLength
                          },
                          stats: {
                            total_requests: stats.totalRequests,
                            success_requests: stats.successRequests,
                            failed_requests: stats.failedRequests,
                            success_rate: stats.totalRequests > 0 ? ((stats.successRequests / stats.totalRequests) * 100).toFixed(2) + "%" : "N/A",
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
        
        // 支持两种格式:
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
        
        // 支持两种格式:
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
      
      // GET: 列出所有tokens(带掩码和详细信息)
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

    /* 会话管理API - 需要管理员权限 */
    if (path==="/v1/admin/sessions"){
      if (!isAdminAuthorized(req)) {
        log.warn({ 事件:"管理员鉴权失败", 请求ID:reqId, 路径:path });
        return forbidden();
      }
      
      // GET: 查看会话(需要session_id参数)
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
      // 仅服务端模式:使用下游token,不重试
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
      
      // 正常模式:使用token池和重试
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
              // 已经是 OpenAI 格式,直接返回
              openaiFormat = data;
            } else {
              // 未知格式,返回空列表
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
      // 如果启用 auto_session 或没有提供 session_id 但启用了长上下文,则自动生成会话 ID
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
      
      // ============ kb_list 处理(必须字段,UUID v4 数组) ============
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
          // 会话中没有,生成新的 UUID v4 数组
          finalKbList = [crypto.randomUUID()];
          await sessionManager.setKbList(effectiveSessionId, finalKbList);
          log.info({ 事件:"生成新kb_list", sessionId: effectiveSessionId, kb_list: finalKbList, ...{ 请求ID: reqId } });
        }
      } else {
        // 没有会话,生成新的 UUID v4 数组
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

      // ============ 思考注入 ============
      if (CONFIG.enableThinkingInjection && normMessages.length > 0) {
        // 检查是否已有system消息
        const hasSystemMessage = normMessages.some(m => m.role === "system");
        
        if (!hasSystemMessage) {
          // 如果没有system消息,在最前面添加
          normMessages.unshift({
            role: "system",
            content: CONFIG.thinkingPrompt
          });
          log.debug({ 事件:"注入思考提示(前置)", 提示: CONFIG.thinkingPrompt.slice(0, 50) + "...", ...{ 请求ID: reqId } });
        } else {
          // 如果已有system消息,追加到第一个system消息的内容后
          const firstSystemIdx = normMessages.findIndex(m => m.role === "system");
          if (firstSystemIdx !== -1) {
            normMessages[firstSystemIdx].content += "\n\n" + CONFIG.thinkingPrompt;
            log.debug({ 事件:"注入思考提示(追加)", 提示: CONFIG.thinkingPrompt.slice(0, 50) + "...", ...{ 请求ID: reqId } });
          }
        }
      }

      const isExternalStream = !!stream;
      const maxTok = Number.isFinite(max_completion_tokens) ? max_completion_tokens
      : Number.isFinite(max_tokens) ? max_tokens : undefined;

      // ============ MCP工具支持 ============
      // 只有在用户明确提供tools时才使用,否则不自动注入
      // 某些模型可能不支持tools参数,导致上游报错
      const mcpTools = tools && tools.length > 0 
        ? tools 
        : (CONFIG.enableMCP && tool_choice 
          ? MCP_TOOLS.filter(t => CONFIG.mcpTools.includes(t.function.name))
          : undefined);

      const upstreamBody:any = {
        messages: normMessages,
        kb_list: finalKbList,  // 必须字段,UUID v4 数组
      stream: isExternalStream,
      ...(model? {model}:{}),
        ...(Number.isFinite(maxTok)? { max_tokens:maxTok }:{}),
        ...(mcpTools && mcpTools.length > 0 ? { tools: mcpTools } : {}),
        ...(tool_choice ? { tool_choice } : {})
      };
      
      const modelName = model ?? "flowith";
      
      log.info({ 
        事件:"请求处理", 
        模型: modelName, 
        消息数: normMessages.length,
        会话ID: effectiveSessionId ?? "无",
        是否有会话: !!effectiveSessionId,
        自动会话: effectiveSessionId && !session_id,
        kb_list: finalKbList,
        kb_list数量: finalKbList.length,
        启用思考: CONFIG.enableThinkingInjection,
        启用MCP: CONFIG.enableMCP,
        工具数: mcpTools?.length ?? 0,
        模式: serverOnlyMode ? "仅服务端" : "正常",
        ...{ 请求ID: reqId }
      });
      
      // ============ 仅服务端模式:不重试,直接透传 ============
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
      
      // ============ 正常模式:使用token池和重试 ============
      let attempt = 0, lastErr:any=null, lastStatus=0, lastContent="", lastHeaders:Headers|null=null;
      let needsRetry = false;
      let lastTokenIdx = -1;
      
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
                  // 如果还有未输出的thinking,先输出
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

                      // 处理多种分隔符:\n\n(SSE标准)、\n(text/plain)、}\n(JSON流)
                      let processedAny = false;
                      
                      // 优先处理 \n\n 分隔(SSE标准格式)
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
                            
                            // 检测是否为thinking内容(仅当启用时)
                            const isThinking = CONFIG.enableThinkingTags && 
                              (obj?.type === "thinking" || delta.includes("<think>") || delta.includes("</think>"));
                            
                            if (CONFIG.enableThinkingTags && (isThinking || isInThinking)) {
                              isInThinking = true;
                              thinkingBuffer += delta;
                              
                              // 输出thinking头部(只输出一次)
                              if (!hasOutputThinkingHeader) {
                                hasOutputThinkingHeader = true;
                                const headerChunk = openaiChunk(modelName, `\n<thinking>\n`);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(headerChunk)}\n\n`));
                              }
                              
                              // 立即输出thinking内容(不等待完整)
                              if (delta) {
                                const thinkChunk = openaiChunk(modelName, delta);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(thinkChunk)}\n\n`));
                              }
                              
                              // 检测thinking结束
                              if (delta.includes("</think>") || obj?.thinking_complete) {
                                isInThinking = false;
                                const endChunk = openaiChunk(modelName, `\n</thinking>\n\n`);
                                controller.enqueue(enc.encode(`data: ${JSON.stringify(endChunk)}\n\n`));
                              }
                            } else {
                              // 正常内容
                              if (delta) {
                                // 性能优化:复用chunk对象
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
                          // JSON解析失败,尝试作为纯文本处理
                          const { delta, isFinal } = extractDeltaFromTextChunk(data);
                          if (delta && delta !== "[DONE]") {
                            const chunk = openaiChunk(modelName, delta);
                            controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
                          }
                          if (isFinal || delta === "[DONE]") { safeClose(); return; }
                        }
                      }
                      
                      // 如果没有处理 \n\n 分隔符,尝试处理单个 \n(纯文本流)
                      if (!processedAny && buf.includes("\n")) {
                        const lines = buf.split("\n");
                        buf = lines.pop() || "";  // 保留最后一行(可能不完整)
                        
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
            
            // 2. 检查上游错误状态码(如果配置了可重试的状态码)
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
                // 尝试解析为 JSON(上游可能返回结构化错误)
                responseBody = content ? JSON.parse(content) : openaiNonStream(modelName, content);
              } catch {
                // 解析失败,包装为标准格式
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
          needsRetry = true;
          log.warn({ 
            事件:"上游调用异常(重试点)", 
            错误:String((e as any)?.message ?? e), 
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
        
        // 预测下一个将使用的密钥(用于日志显示)
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
          // 解析失败,包装为标准错误格式
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

    // Claude API 兼容端点:/v1/messages
    // 注意:目前只支持转换提示,实际使用请调用 /v1/chat/completions
    if (req.method==="POST" && path==="/v1/messages" && CONFIG.enableClaudeAPI){
      let claudeBody:any = {}; 
      try { claudeBody = await req.json(); } catch { return badRequest("Invalid JSON body."); }
      
      const { model, messages, system, max_tokens, stream } = claudeBody ?? {};
      if (!Array.isArray(messages) || messages.length===0) {
        return badRequest("`messages` is required and must be a non-empty array.");
      }
      
      // 转换为 OpenAI 格式
      const convertedMessages = normalizeMessages(messages);
      const finalMessages = system && typeof system === "string" 
        ? [{ role: "system", content: system }, ...convertedMessages]
        : convertedMessages;
      
      return jsonResponse({ 
        message: "Please use /v1/chat/completions endpoint with OpenAI format",
        converted_request: {
          url: "/v1/chat/completions",
          method: "POST",
          headers: { "Authorization": "Bearer YOUR_API_KEY", "Content-Type": "application/json" },
          body: {
            model: model ?? "claude-3-5-sonnet",
            messages: finalMessages,
            stream: stream ?? false,
            max_tokens
          }
        }
      }, 200);
    }

    stats.failedRequests++;
    return jsonResponse({ error:{ message:"Not Found", type:"not_found"} }, 404);
  } catch (e){
    stats.failedRequests++;
    log.error({ 事件:"处理异常", 错误:String((e as any)?.message ?? e), 堆栈: (e as any)?.stack, 请求ID:reqId });
    return gatewayError(e);
  }
}, { port: PORT });

const rsyncMode = (Deno.env.get("RSYNC") ?? "0").trim() === "1";
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
    仅服务端模式: CONFIG.serverOnly,
    Claude_API: CONFIG.enableClaudeAPI
  }
});
