// Isolated snapshot route: no IP expansion and no legacy token changes.
const TTL = 7 * 24 * 60 * 60, MAX_BYTES = 1024 * 1024;
const headers = {'cache-control': 'no-store', 'access-control-allow-origin': '*', 'x-content-type-options': 'nosniff'};
function reply(body, status = 200, type = 'application/json; charset=utf-8') {
  return new Response(type.startsWith('application/json') ? JSON.stringify(body) : body,
    {status, headers: {...headers, 'content-type': type}});
}
function randomHex(size) {
  return Array.from(crypto.getRandomValues(new Uint8Array(size)), b => b.toString(16).padStart(2, '0')).join('');
}
export async function sha256(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))),
    b => b.toString(16).padStart(2, '0')).join('');
}
function validConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return false;
  const nodes = config.proxies, groups = config['proxy-groups'];
  if (!Array.isArray(nodes) || !nodes.length || nodes.length > 500) return false;
  const names = new Set();
  for (const n of nodes) {
    if (!n || typeof n.name !== 'string' || !n.name || names.has(n.name) ||
        typeof n.server !== 'string' || !n.server || !Number.isInteger(n.port) || n.port < 1 || n.port > 65535 ||
        !['vmess', 'vless', 'trojan', 'ss', 'socks5', 'http'].includes(n.type)) return false;
    names.add(n.name);
  }
  return Array.isArray(groups) && groups.length === 1 && groups[0].type === 'url-test' &&
    groups[0].name === '最低延迟' && Array.isArray(groups[0].proxies) &&
    groups[0].proxies.length === names.size && new Set(groups[0].proxies).size === names.size &&
    groups[0].proxies.every(n => names.has(n)) &&
    Array.isArray(config.rules) && config.rules.includes('MATCH,最低延迟');
}
export async function handleExport(request, env, url) {
  if (!env.SUB_STORE) return reply({error: '订阅存储尚未配置'}, 503);
  try {
    if (!(request.headers.get('content-type') || '').startsWith('application/json')) return reply({error: '需要 JSON 配置'}, 415);
    if (Number(request.headers.get('content-length')) > MAX_BYTES) return reply({error: '配置过大'}, 413);
    const reader = request.body?.getReader();
    if (!reader) return reply({error: '配置为空'}, 400);
    const chunks = []; let bytes = 0;
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_BYTES) { await reader.cancel(); return reply({error: '配置过大'}, 413); }
      chunks.push(value);
    }
    const buffer = new Uint8Array(bytes); let offset = 0;
    for (const c of chunks) {buffer.set(c, offset); offset += c.length;}
    const body = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(buffer));
    // JSON is valid YAML and loads in Mihomo. Keep the supplied text byte-for-byte.
    if (typeof body.configText !== 'string' || !validConfig(JSON.parse(body.configText)) ||
        !Number.isFinite(body.resultAt) || body.resultAt <= 0) return reply({error: '配置或结果时间无效'}, 400);
    const config = JSON.parse(body.configText), contentSha256 = await sha256(body.configText);
    if (body.sha256 !== contentSha256 || body.nodeCount !== config.proxies.length) return reply({error: '配置校验不一致'}, 400);
    const id = randomHex(16), token = randomHex(32), expiresAt = Math.floor(Date.now() / 1000) + TTL;
    const record = {configText: body.configText, tokenHash: await sha256(token), contentSha256,
      nodeCount: config.proxies.length, resultAt: body.resultAt, expiresAt};
    await env.SUB_STORE.put(`export:${id}`, JSON.stringify(record), {expirationTtl: TTL});
    const link = new URL(`/sub/export-${id}`, url.origin);
    link.searchParams.set('target', 'clash'); link.searchParams.set('token', token);
    return reply({url: link.href, nodeCount: record.nodeCount, resultAt: record.resultAt, expiresAt, sha256: contentSha256});
  } catch { return reply({error: '导出失败，请检查配置或稍后重试'}, 400); }
}
export async function handleExportSub(url, env) {
  const match = /^\/sub\/export-([a-f0-9]{32})$/.exec(url.pathname);
  if (!match || !env.SUB_STORE) return reply({error: '订阅不存在或已过期'}, 404);
  try {
    const raw = await env.SUB_STORE.get(`export:${match[1]}`);
    if (!raw) return reply({error: '订阅不存在或已过期'}, 404);
    const record = JSON.parse(raw), token = url.searchParams.get('token') || '';
    if (!/^[a-f0-9]{64}$/.test(token) || await sha256(token) !== record.tokenHash) return reply({error: '订阅令牌无效'}, 403);
    if (record.expiresAt <= Date.now() / 1000) return reply({error: '订阅已过期'}, 410);
    return reply(record.configText, 200, 'text/yaml; charset=utf-8');
  } catch { return reply({error: '订阅暂不可用'}, 503); }
}
