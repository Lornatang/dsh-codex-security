import { ROUTE_PREFIX } from './constants.js';
function sendJson(res, status, payload) {
    const body = JSON.stringify(payload);
    res.statusCode = status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.end(body);
}
async function readBody(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
        size += buffer.byteLength;
        if (size > 1024 * 1024)
            throw new Error('request body too large');
        chunks.push(buffer);
    }
    if (size === 0)
        return {};
    const text = Buffer.concat(chunks).toString('utf8');
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
        throw new Error('request body must be a JSON object');
    return parsed;
}
function queryOf(url) {
    const query = {};
    for (const [key, value] of url.searchParams.entries())
        query[key] = value;
    return query;
}
function sendFile(res, content, mediaType, filename) {
    res.statusCode = 200;
    res.setHeader('content-type', mediaType + '; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('content-disposition', 'attachment; filename="' + filename + '"');
    res.end(content);
}
function scanIdFromPath(pathname) {
    const parts = pathname.split('/').filter(Boolean);
    return parts.length >= 2 ? parts[1] : undefined;
}
export async function handleRequest(service, req, res) {
    try {
        const url = new URL(req.url ?? '/', 'http://localhost');
        const pathname = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
        if (!pathname.startsWith(ROUTE_PREFIX)) {
            sendJson(res, 404, { ok: false, error: 'not found' });
            return;
        }
        const route = pathname.slice(ROUTE_PREFIX.length) || '/';
        const method = req.method ?? 'GET';
        const query = queryOf(url);
        if (route === '/status' && method === 'GET') {
            sendJson(res, 200, await service.status());
            return;
        }
        if (route === '/config' && method === 'GET') {
            sendJson(res, 200, { ok: true, config: service.publicConfig() });
            return;
        }
        if (route === '/scans' && method === 'GET') {
            sendJson(res, 200, await service.listScans(query));
            return;
        }
        if (route === '/scans' && method === 'POST') {
            sendJson(res, 405, { ok: false, error: 'method not allowed' });
            return;
        }
        if (route === '/findings' && method === 'GET') {
            sendJson(res, 200, await service.listFindings(query));
            return;
        }
        const scanMatch = /^\/scans\/(cs_[a-f0-9]{24})(\/[a-z]+)?$/.exec(route);
        if (scanMatch) {
            const scanId = scanMatch[1];
            const action = scanMatch[2];
            if (!action && method === 'GET') {
                sendJson(res, 200, await service.getScan({ scanId }));
                return;
            }
            if (action === '/triage' && method === 'POST') {
                const body = await readBody(req);
                sendJson(res, 200, await service.setFindingTriage({ scanId, findingId: body['findingId'], status: body['status'], note: body['note'] }));
                return;
            }
            if (action === '/remediation' && method === 'POST') {
                const body = await readBody(req);
                sendJson(res, 200, await service.setFindingRemediation({ scanId, findingId: body['findingId'], remediation: body['remediation'], status: body['status'] }));
                return;
            }
            sendJson(res, 404, { ok: false, error: 'not found' });
            return;
        }
        const exportMatch = /^\/export\/(cs_[a-f0-9]{24})$/.exec(route);
        if (exportMatch && method === 'GET') {
            const scanId = exportMatch[1];
            const format = typeof query['format'] === 'string' ? query['format'] : 'markdown';
            const exported = await service.exportContent(scanId, format);
            sendFile(res, exported.content, exported.mediaType, exported.filename);
            return;
        }
        if (route === '/' && method === 'GET') {
            sendJson(res, 200, { ok: true, name: 'codex-security', routes: ['/status', '/config', '/scans', '/scans/:id', '/findings', '/export/:id?format=sarif|json|csv|markdown', 'POST /scans/:id/triage', 'POST /scans/:id/remediation'] });
            return;
        }
        sendJson(res, 404, { ok: false, error: 'not found' });
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const status = /scan not found/.test(message) ? 404 : /required|must be|invalid|format|refusing/.test(message) ? 400 : 500;
        sendJson(res, status, { ok: false, error: message });
    }
}
export function bindRoutes(ctx, service) {
    let disposeRoute;
    const register = () => {
        const server = (ctx.get?.('webServer') ?? ctx.get?.('httpServer'));
        if (!server)
            return;
        disposeRoute?.();
        disposeRoute = server.register({ kind: 'prefix', path: ROUTE_PREFIX, handler: (req, res) => handleRequest(service, req, res) });
    };
    register();
    const off = ctx.on?.('internal/service', () => { register(); });
    return () => { off?.(); disposeRoute?.(); disposeRoute = undefined; };
}
export { scanIdFromPath };
