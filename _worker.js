export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. 获取目标 URL 并加入畸形 URL 修复逻辑 (应对 CF 吞噬双斜杠 Bug)
    let targetUrlStr = url.searchParams.get('url');
    if (!targetUrlStr) {
      targetUrlStr = url.pathname.substring(1) + url.search;
      if (targetUrlStr.startsWith('http:/') && !targetUrlStr.startsWith('http://')) {
        targetUrlStr = targetUrlStr.replace('http:/', 'http://');
      } else if (targetUrlStr.startsWith('https:/') && !targetUrlStr.startsWith('https://')) {
        targetUrlStr = targetUrlStr.replace('https:/', 'https://');
      }
    }

    // 如果未提供目标，返回使用说明页面
    if (!targetUrlStr || !/^https?:\/\//i.test(targetUrlStr)) {
      return new Response(
        '<h2>CF反代引擎正常运行</h2><p>使用方法：在当前网址后面加上 <code>/https://你的真实订阅链接</code> 或 <code>?url=https://...</code></p>', 
        { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      );
    }

    // 2. 处理 CORS 预检
    if (request.method === 'OPTIONS') {
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, HEAD',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, User-Agent, Accept, Accept-Language',
        'Access-Control-Max-Age': '86400'
      };
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 3. 可选白名单拦截 (通过环境变量 ALLOWLIST 注入)
    const allowlist = (env.ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
    let targetUrl;
    try {
      targetUrl = new URL(targetUrlStr);
    } catch (e) {
      return new Response('目标 URL 格式非法', { status: 400 });
    }

    if (allowlist.length && !allowlist.includes(targetUrl.hostname)) {
      return new Response('目标域名不在允许列表中', { status: 403 });
    }

    // 4. 头部处理与严格 UA 伪装
    const clientKeywords = ['clash', 'mihomo', 'stash', 'surge', 'quantumult', 'shadowrocket', 'loon', 'choc', 'sing-box', 'singbox', 'surfboard', 'v2ray', 'nekobox', 'nekoray', 'passwall'];
    const incoming = request.clone();
    const adaptedHeaders = new Headers(incoming.headers);
    const incomingUA = (adaptedHeaders.get('User-Agent') || '').toLowerCase();
    
    // 判定是否为已知合法客户端
    const isClient = clientKeywords.some(k => incomingUA.includes(k));

    // 删除代理痕迹，防止环回检测
    adaptedHeaders.delete('cf-connecting-ip');
    adaptedHeaders.delete('cf-ray');
    adaptedHeaders.delete('cf-visitor');
    adaptedHeaders.delete('x-forwarded-for');
    adaptedHeaders.delete('x-forwarded-proto');
    adaptedHeaders.delete('referer');

    // 强制对齐 Host 与 Origin，突破 SNI 阻断
    adaptedHeaders.set('Host', targetUrl.hostname);
    if (adaptedHeaders.get('Origin')) {
      adaptedHeaders.set('Origin', `${targetUrl.protocol}//${targetUrl.hostname}`);
    }

    // 核心 UA 逻辑：如果没有匹配到合法客户端 UA（即无 UA 或是浏览器等不规范 UA），则一律覆写为指定的 clash 版本
    if (!isClient) {
      adaptedHeaders.set('User-Agent', 'clash-verge/2.5.1');
    }

    // 5. 连接超时控制
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, 10000); // 严格设定 10 秒超时

    try {
      // 6. 发起代理请求 (开启底层 SSL 宽容机制)
      const proxyReq = new Request(targetUrl.toString(), {
        method: incoming.method,
        headers: adaptedHeaders,
        body: (incoming.method === 'GET' || incoming.method === 'HEAD') ? null : incoming.body,
        redirect: 'follow',
        signal: controller.signal,
        cf: {
          insecureSkipVerify: true, // 允许非法/自签证书
          cacheTtl: 0 // 禁用缓存
        }
      });

      const resp = await fetch(proxyReq);
      clearTimeout(timeoutId);

      // 7. 数据透传与响应头重写
      const newHeaders = new Headers(resp.headers);
      newHeaders.set('Access-Control-Allow-Origin', '*');
      newHeaders.delete('content-security-policy');
      newHeaders.delete('strict-transport-security');

      return new Response(resp.body, { status: resp.status, headers: newHeaders });

    } catch (e) {
      clearTimeout(timeoutId);
      if (e.name === 'AbortError') {
        return new Response('代理请求超时 (10s)：目标服务器未响应', { status: 504 });
      }
      return new Response('代理请求时出错: ' + e.message, { status: 500 });
    }
  }
};
