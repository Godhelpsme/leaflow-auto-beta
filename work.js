// ============================================================================
// Discord Webhook Proxy - Production Ready
// 功能: 身份验证 + 速率限制 + 重试逻辑 + 日志
// ============================================================================

const CONFIG = {
  // 速率限制配置
  RATE_LIMITS: {
    SHORT_WINDOW: 2000,      // 2 秒窗口
    SHORT_MAX: 5,            // Discord 官方限制：每 2 秒 5 个请求
    LONG_WINDOW: 60000,      // 1 分钟窗口
    LONG_MAX: 30,            // 保守估计：每分钟 30 个请求
  },
  // 重试配置
  RETRY: {
    MAX_ATTEMPTS: 3,
    INITIAL_DELAY: 1000,     // 初始延迟 1 秒
    MAX_DELAY: 8000,         // 最大延迟 8 秒
    JITTER_FACTOR: 0.1,      // 抖动因子 ±10%
  },
};

// ============================================================================
// 日志系统
// ============================================================================
class Logger {
  constructor(context) {
    this.context = context;
    this.startTime = Date.now();
  }

  log(level, message, data = {}) {
    const elapsed = Date.now() - this.startTime;
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      elapsed: `${elapsed}ms`,
      ...data,
    };

    if (level === 'error') {
      console.error(JSON.stringify(logEntry));
    } else {
      console.log(JSON.stringify(logEntry));
    }
  }

  info(message, data) {
    this.log('INFO', message, data);
  }

  warn(message, data) {
    this.log('WARN', message, data);
  }

  error(message, data) {
    this.log('ERROR', message, data);
  }

  debug(message, data) {
    // Cloudflare Workers 中通过 env 传递环境变量，不使用 process.env
    // 如需启用 debug，在 Worker 配置中设置 DEBUG 环境变量
    // this.log('DEBUG', message, data);
  }
}

// ============================================================================
// 速率限制器（纯内存）
// ============================================================================
class RateLimiter {
  constructor(webhookId) {
    this.webhookId = webhookId;
    this.shortRequests = [];
    this.longRequests = [];
  }

  cleanup() {
    const now = Date.now();
    this.shortRequests = this.shortRequests.filter(
      (time) => now - time < CONFIG.RATE_LIMITS.SHORT_WINDOW
    );
    this.longRequests = this.longRequests.filter(
      (time) => now - time < CONFIG.RATE_LIMITS.LONG_WINDOW
    );
  }

  canProcess() {
    this.cleanup();
    return (
      this.shortRequests.length < CONFIG.RATE_LIMITS.SHORT_MAX &&
      this.longRequests.length < CONFIG.RATE_LIMITS.LONG_MAX
    );
  }

  getWaitTime() {
    const now = Date.now();
    let waitTime = 0;

    if (this.shortRequests.length >= CONFIG.RATE_LIMITS.SHORT_MAX) {
      const oldestRequest = this.shortRequests[0];
      waitTime = Math.max(
        waitTime,
        CONFIG.RATE_LIMITS.SHORT_WINDOW - (now - oldestRequest)
      );
    }

    if (this.longRequests.length >= CONFIG.RATE_LIMITS.LONG_MAX) {
      const oldestRequest = this.longRequests[0];
      waitTime = Math.max(
        waitTime,
        CONFIG.RATE_LIMITS.LONG_WINDOW - (now - oldestRequest)
      );
    }

    return Math.max(0, waitTime);
  }

  recordRequest() {
    const now = Date.now();
    this.shortRequests.push(now);
    this.longRequests.push(now);
  }
}

// ============================================================================
// 重试逻辑（指数退避 + 抖动）
// ============================================================================
async function fetchWithRetry(url, options, logger) {
  let lastError;

  for (let attempt = 1; attempt <= CONFIG.RETRY.MAX_ATTEMPTS; attempt++) {
    try {
      const response = await fetch(url, options);

      // 如果成功，直接返回
      if (response.ok) {
        logger.info('Request succeeded', { attempt, status: response.status });
        return response;
      }

      // 如果是 429（限流），则重试
      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') || '5');
        lastError = {
          status: 429,
          message: `Rate limited by Discord, retry after ${retryAfter}s`,
          retryAfter,
        };
        logger.warn('Discord rate limit hit', { attempt, retryAfter });

        if (attempt < CONFIG.RETRY.MAX_ATTEMPTS) {
          const delay = retryAfter * 1000;
          logger.info('Waiting before retry', { delay });
          await sleep(delay);
          continue;
        }
      }

      // 其他错误，返回原始响应
      logger.info('Request completed', { attempt, status: response.status });
      return response;
    } catch (error) {
      lastError = error;
      logger.error(`Attempt ${attempt} failed`, { error: error.message });

      if (attempt < CONFIG.RETRY.MAX_ATTEMPTS) {
        // 计算指数退避延迟
        const delay = calculateBackoff(attempt);
        logger.info('Retrying after backoff', { delay });
        await sleep(delay);
      }
    }
  }

  // 所有重试都失败了
  throw lastError || new Error('All retry attempts failed');
}

function calculateBackoff(attempt) {
  // 指数退避: 1s, 2s, 4s, 8s...
  let delay = CONFIG.RETRY.INITIAL_DELAY * Math.pow(2, attempt - 1);
  delay = Math.min(delay, CONFIG.RETRY.MAX_DELAY);

  // 加入抖动 ±10%
  const jitter = delay * CONFIG.RETRY.JITTER_FACTOR;
  const variance = (Math.random() - 0.5) * 2 * jitter;

  return Math.max(0, delay + variance);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================================
// 请求验证
// ============================================================================
function validateAuthToken(request, env, logger) {
  const authHeader = request.headers.get('Authorization');
  const expectedToken = env.WEBHOOK_AUTH_TOKEN;

  if (!authHeader) {
    logger.warn('Missing Authorization header');
    return false;
  }

  const token = authHeader.replace('Bearer ', '').trim();

  if (token !== expectedToken) {
    logger.warn('Invalid token');
    return false;
  }

  return true;
}

function validateWebhookPath(path) {
  // 格式应该是: /webhooks/ID/TOKEN
  // 其中 ID 是纯数字，TOKEN 是字母数字和下划线的组合
  const match = path.match(/^\/webhooks\/(\d+)\/([a-zA-Z0-9_-]+)$/);
  return !!match;
}

// ============================================================================
// CORS 处理
// ============================================================================
function handleCORS(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400', // 24 小时
      },
    });
  }

  return null;
}

function addCORSHeaders(response, request) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', request.headers.get('Origin') || '*');
  headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

// ============================================================================
// 主处理函数
// ============================================================================
async function handleRequest(request, env, ctx) {
  const logger = new Logger(ctx);
  const url = new URL(request.url);
  const webhookPath = url.pathname;

  logger.info('Incoming request', {
    method: request.method,
    path: webhookPath,
  });

  // ========== CORS 处理 ==========
  const corsResponse = handleCORS(request);
  if (corsResponse) {
    logger.info('CORS preflight handled');
    return corsResponse;
  }

  // ========== 方法验证 ==========
  if (request.method !== 'POST') {
    logger.warn('Invalid method', { method: request.method });
    return createErrorResponse('Method Not Allowed', 405, 'Only POST requests are supported');
  }

  // ========== 身份验证 ==========
  if (!validateAuthToken(request, env, logger)) {
    logger.error('Authentication failed');
    return createErrorResponse('Unauthorized', 401, 'Invalid or missing authentication token');
  }

  logger.info('Authentication passed');

  // ========== 路径验证 ==========
  if (!validateWebhookPath(webhookPath)) {
    logger.error('Invalid webhook path format', { path: webhookPath });
    return createErrorResponse('Bad Request', 400, 'Invalid webhook path format. Expected: /webhooks/{ID}/{TOKEN}');
  }

  // 提取 webhook ID 用于速率限制
  const webhookId = webhookPath.split('/')[2];

  // ========== 速率限制检查 ==========
  const rateLimiter = new RateLimiter(webhookId);

  if (!rateLimiter.canProcess()) {
    const waitTime = rateLimiter.getWaitTime();
    logger.warn('Rate limit exceeded', { webhookId, waitTime });
    return createErrorResponse(
      'Too Many Requests',
      429,
      `Rate limited. Please retry after ${Math.ceil(waitTime / 1000)} seconds`,
      { 'Retry-After': Math.ceil(waitTime / 1000) }
    );
  }

  try {
    // ========== 准备 Discord 请求 ==========
    const discordUrl = `https://discord.com/api${webhookPath}`;
    const body = await request.text();

    // 验证 JSON 格式
    try {
      JSON.parse(body);
    } catch (parseError) {
      logger.error('Invalid JSON in request body');
      return createErrorResponse('Bad Request', 400, 'Request body must be valid JSON');
    }

    logger.debug('Forwarding to Discord', { url: discordUrl, bodyLength: body.length });

    // ========== 发送到 Discord（带重试） ==========
    const response = await fetchWithRetry(
      discordUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body,
      },
      logger
    );

    // 记录请求（用于速率限制）
    rateLimiter.recordRequest();

    logger.info('Request forwarded successfully', { status: response.status });

    // ========== 返回响应 ==========
    const proxyResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: {
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
      },
    });

    return addCORSHeaders(proxyResponse, request);
  } catch (error) {
    logger.error('Request failed', {
      error: error.message,
      stack: error.stack,
    });

    return createErrorResponse(
      'Bad Gateway',
      502,
      'Failed to forward request to Discord. This may be a temporary issue.'
    );
  }
}

// ============================================================================
// 错误响应辅助函数
// ============================================================================
function createErrorResponse(title, status, message, extraHeaders = {}) {
  return new Response(
    JSON.stringify({
      error: title,
      message,
      timestamp: new Date().toISOString(),
    }),
    {
      status,
      headers: {
        'Content-Type': 'application/json',
        ...extraHeaders,
      },
    }
  );
}

// ============================================================================
// 导出
// ============================================================================
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
};
