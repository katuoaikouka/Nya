const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const SECRET_KEY = 0xAB; 

// 既存の難読化（XOR）
const transform = (buf) => Buffer.from(buf).map(b => b ^ SECRET_KEY);

// CSS内の url() 指定を正規化する補助関数
const rewriteCSS = (css, targetUrl) => {
    return css.replace(/url\(['"]?([^'"]+)['"]?\)/g, (match, p1) => {
        try {
            if (p1.startsWith('data:') || p1.startsWith('http')) return match;
            return `url("${new URL(p1, targetUrl).href}")`;
        } catch(e) {
            return match;
        }
    });
};

// リソース書き換え機能: HTMLおよびCSS内のパスを正規化
const rewriteResources = (content, targetUrl, contentType) => {
    // HTMLのリライト
    if (contentType.includes('text/html')) {
        const $ = cheerio.load(content);
        const urlObj = new URL(targetUrl);

        // 1. <base>タグを挿入して相対パスの基準をターゲットドメインに固定
        $('head').prepend(`<base href="${urlObj.origin}${urlObj.pathname}">`);
        
        // --- 動的サイト対応: JSインジェクション ---
        const injectAdvancedHooks = `
        <script>
        (function() {
            const TARGET_URL = new URL("${targetUrl}");
            const WS_PROXY_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;

            // 1. window.location のモック (読み取り偽装と遷移の親転送)
            const fakeLocation = {};
            ['href', 'hostname', 'origin', 'protocol', 'port', 'pathname', 'search', 'hash'].forEach(prop => {
                Object.defineProperty(fakeLocation, prop, {
                    get: () => TARGET_URL[prop],
                    set: (val) => { window.parent.postMessage({type: 'nav', url: new URL(val, TARGET_URL.href).href}, '*'); }
                });
            });
            try { 
                delete window.document.location; 
                window.document.location = fakeLocation; 
            } catch(e) {}

            // 2. Cookieのフック (Domain/Path制約の除去)
            const cookieSetter = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie').set;
            Object.defineProperty(document, 'cookie', {
                set: function(val) {
                    let parts = val.split(';').map(p => p.trim());
                    const newParts = parts.filter(p => !p.toLowerCase().startsWith('domain=') && !p.toLowerCase().startsWith('path='));
                    newParts.push('Path=/');
                    cookieSetter.call(document, newParts.join('; '));
                }
            });

            // 3. WebSocketのフック (WS over WS リレー)
            const OriginalWebSocket = window.WebSocket;
            window.WebSocket = function(url, protocols) {
                const absoluteUrl = new URL(url, TARGET_URL.href).href;
                // プロトコルヘッダーを利用してターゲットURLをサーバーに伝達
                const ws = new OriginalWebSocket(WS_PROXY_URL, ['proxy-protocol', btoa(absoluteUrl)]);
                Object.defineProperty(ws, 'url', { get: () => absoluteUrl });
                return ws;
            };
            window.WebSocket.prototype = OriginalWebSocket.prototype;

            // 4. Workerのフック (相対パス解決)
            const OriginalWorker = window.Worker;
            window.Worker = function(scriptURL, options) {
                return new OriginalWorker(new URL(scriptURL, TARGET_URL.href).href, options);
            };
        })();
        </script>
        `;
        $('head').prepend(injectAdvancedHooks);

        // ゲーム用にCanvasを全画面表示にするスタイルを強制注入
        $('head').append(`
            <style>
                body, html { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; }
                canvas { display: block; width: 100vw; height: 100vh; }
            </style>
        `);

        // 2. a, img, link, script 等のURL属性を修正（絶対パス化）
        $('a, img, link, script, source, iframe, form').each((i, el) => {
            ['href', 'src', 'action'].forEach(attr => {
                const val = $(el).attr(attr);
                if (val && !val.startsWith('data:') && !val.startsWith('#') && !val.startsWith('javascript:')) {
                    try {
                        $(el).attr(attr, new URL(val, targetUrl).href);
                    } catch (e) {}
                }
            });
        });

        // 3. インラインCSSのリライト
        $('style').each((i, el) => {
            const css = $(el).text();
            $(el).text(rewriteCSS(css, targetUrl));
        });

        // 4. セキュリティポリシー(CSP)およびフレーム制限の解除
        $('meta[http-equiv*="Content-Security-Policy" i]').remove();
        $('meta[name*="viewport"]').attr('content', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no');

        return $.html();
    }
    
    // CSSファイル単体のリライト
    if (contentType.includes('text/css')) {
        return rewriteCSS(content.toString(), targetUrl);
    }
    
    return content;
};

app.use(express.static('public'));

wss.on('connection', (ws, req) => {
    const jar = new Map();
    const protocols = req.headers['sec-websocket-protocol'];

    // --- WebSocketプロキシ (リレーモード) ---
    if (protocols && protocols.includes('proxy-protocol')) {
        try {
            const targetWsUrl = Buffer.from(protocols.split(',')[1].trim(), 'base64').toString();
            const targetWs = new WebSocket(targetWsUrl);

            // ターゲットからクライアントへ (難読化して転送)
            targetWs.on('message', (data) => { 
                if (ws.readyState === WebSocket.OPEN) ws.send(transform(data)); 
            });

            // クライアントからターゲットへ (難読化解除して転送)
            ws.on('message', (msg) => { 
                if (targetWs.readyState === WebSocket.OPEN) targetWs.send(transform(msg)); 
            });

            targetWs.on('close', () => ws.close());
            ws.on('close', () => targetWs.close());
            targetWs.on('error', () => ws.close());
            return;
        } catch (e) {
            ws.close();
            return;
        }
    }

    // --- 通常のHTTPリクエスト中継モード ---
    ws.on('message', async (msg) => {
        try {
            const decrypted = transform(msg).toString();
            const { url, method, headers, data } = JSON.parse(decrypted);
            const urlObj = new URL(url);
            const host = urlObj.hostname;

            const res = await axios({
                url,
                method: method || 'GET',
                data: data || null,
                headers: {
                    ...headers,
                    'Cookie': jar.get(host) || '',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                    'Referer': url,
                    'Origin': urlObj.origin
                },
                responseType: 'arraybuffer',
                validateStatus: false
            });

            if (res.headers['set-cookie']) {
                jar.set(host, res.headers['set-cookie'].map(c => c.split(';')[0]).join('; '));
            }

            let bodyData = res.data;
            const contentType = res.headers['content-type'] || '';

            if (contentType.includes('text/html') || contentType.includes('text/css')) {
                bodyData = Buffer.from(rewriteResources(bodyData.toString(), url, contentType));
            }

            ws.send(transform(JSON.stringify({
                body: bodyData.toString('base64'),
                status: res.status,
                contentType: contentType,
                url: url
            })));
        } catch (e) {
            ws.send(transform(JSON.stringify({ error: e.message })));
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Stealth Engine active on port ${PORT}`));
