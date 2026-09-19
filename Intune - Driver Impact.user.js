// ==UserScript==
// @name         Intune - Driver Impact
// @namespace    xento.betterintuneui
// @version      0.6.0
// @description  Shows devices affected by Windows Autopatch / Intune driver updates, including model distribution and device details.
// @author       Xento
// @match        https://intune.microsoft.com/*
// @match        https://*.reactblade.portal.azure.net/*
// @match        https://*.reactblade-ms.portal.azure.net/*
// @match        https://*.reactblade-rc.portal.azure.net/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(() => {
    'use strict';

    const SCRIPT = {
        id: 'tm-intune-driver-impact-v1',
        version: '0.6.0',
        debug: true,
        graph: 'https://graph.microsoft.com',
        maxBatch: 20,
        deviceBatchConcurrency: 2,
    };

    const state = {
        driverById: new Map(),
        driverByKey: new Map(),
        tokens: new Map(),
        originalFetch: window.fetch ? window.fetch.bind(window) : null,
        uiObserver: null,
        currentLoadAbort: null,
    };

    const log = (...args) => SCRIPT.debug && console.debug('[TM Driver Impact]', ...args);
    const warn = (...args) => console.warn('[TM Driver Impact]', ...args);

    // ---------------------------------------------------------------------
    // Utility
    // ---------------------------------------------------------------------

    function normalizeText(value) {
        return String(value ?? '').replace(/\s+/g, ' ').trim();
    }

    // Fluent DetailsList cells frequently contain the same value twice:
    // once as visible content and once again in a hidden tooltip. Reading the
    // complete cell.textContent therefore turns e.g. "1.0.0.12" into
    // "1.0.0.121.0.0.12". Always prefer an actually visible value node.
    function visibleCellText(row, automationKey) {
        const cell = row?.querySelector?.(`[data-automation-key="${automationKey}"]`);
        if (!cell) return '';

        const preferred = cell.querySelector(
            'button:not([hidden]), a:not([hidden]), input:not([hidden]), ' +
            '[role="link"]:not([hidden]), span:not([hidden])'
        );
        if (preferred) {
            const value = 'value' in preferred && preferred.value ? preferred.value : preferred.textContent;
            const text = normalizeText(value);
            if (text) return text;
        }

        // Fallback for portal markup variants: clone the cell and remove
        // hidden/assistive tooltip content before taking textContent.
        const clone = cell.cloneNode(true);
        clone.querySelectorAll(
            '[hidden], [aria-hidden="true"], .screenReaderText-134, ' +
            '[style*="position: absolute"][style*="width: 1px"]'
        ).forEach(x => x.remove());
        return normalizeText(clone.textContent);
    }

    function canonicalManufacturer(value) {
        return normalizeText(value)
            .toLocaleLowerCase()
            .replace(/&/g, ' and ')
            .replace(/\b(corporation|corp\.?|incorporated|inc\.?|limited|ltd\.?|company|co\.?)\b/g, ' ')
            .replace(/[^a-z0-9]+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function canonicalDriverName(value, version = '') {
        let text = normalizeText(value).toLocaleLowerCase();
        const v = normalizeText(version).toLocaleLowerCase();
        if (v) text = text.split(v).join(' ');
        return text
            .replace(/\b(driver|update)\b/g, ' ')
            .replace(/\b(corporation|corp\.?|incorporated|inc\.?|limited|ltd\.?|company|co\.?)\b/g, ' ')
            .replace(/[^a-z0-9]+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function driverKey({ name, driverVersion, manufacturer }) {
        return [name, driverVersion, manufacturer]
            .map(x => normalizeText(x).toLocaleLowerCase())
            .join('|');
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#039;');
    }

    function chunk(items, size) {
        const out = [];
        for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
        return out;
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function csvEscape(value) {
        const s = String(value ?? '');
        return /[",\r\n;]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
    }

    function parseJwt(token) {
        try {
            const parts = token.split('.');
            if (parts.length < 2) return null;
            const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
            const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
            const raw = atob(padded);
            const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
            return JSON.parse(new TextDecoder().decode(bytes));
        } catch {
            return null;
        }
    }

    function tokenInfo(token) {
        const claims = parseJwt(token);
        if (!claims) return null;
        const scopes = new Set(String(claims.scp || '').split(/\s+/).filter(Boolean));
        const roles = new Set(Array.isArray(claims.roles) ? claims.roles : []);
        return {
            token,
            claims,
            scopes,
            roles,
            aud: claims.aud,
            exp: Number(claims.exp || 0),
        };
    }

    function tokenIsCurrent(info) {
        return info && (!info.exp || info.exp * 1000 > Date.now() + 60_000);
    }

    function isGraphAudience(aud) {
        const a = String(aud || '').toLowerCase();
        return a === '00000003-0000-0000-c000-000000000000' || a.includes('graph.microsoft.com');
    }

    function hasPermission(info, requested) {
        if (!info) return false;
        if (info.scopes.has(requested) || info.roles.has(requested)) return true;

        const alternatives = {
            'DeviceManagementManagedDevices.Read.All': [
                'DeviceManagementManagedDevices.ReadWrite.All',
            ],
            'Device.Read.All': [
                'Directory.Read.All',
                'Directory.ReadWrite.All',
            ],
            'WindowsUpdates.Read.All': [
                'WindowsUpdates.ReadWrite.All',
            ],
        };
        return (alternatives[requested] || []).some(p => info.scopes.has(p) || info.roles.has(p));
    }

    function addToken(rawToken, source = '', broadcast = true) {
        if (!rawToken || typeof rawToken !== 'string') return;
        const token = rawToken.replace(/^Bearer\s+/i, '').trim();
        if (!token || state.tokens.has(token)) return;
        const info = tokenInfo(token);
        if (!info) return;

        state.tokens.set(token, { ...info, source, observedAt: Date.now() });
        log('Token observed', {
            source,
            aud: info.aud,
            scopes: [...info.scopes],
            roles: [...info.roles],
            exp: info.exp ? new Date(info.exp * 1000).toISOString() : null,
        });

        // Share only in-memory between Intune/ReactBlade frames. Never persist.
        // The Intune shell and ReactBlade frames are different origins, so a token
        // observed in the shell must also be pushed DOWN to existing child frames.
        // v0.2 only posted to parent, which could leave the driver ReactView without
        // the token even though the shell had already captured it.
        if (broadcast) {
            broadcastToken(token, source);
        }
    }

    function getGraphToken(requiredPermissions = []) {
        const candidates = [...state.tokens.values()]
            .filter(tokenIsCurrent)
            .filter(x => isGraphAudience(x.aud))
            .filter(x => requiredPermissions.every(p => hasPermission(x, p)))
            .sort((a, b) => (b.exp || 0) - (a.exp || 0));
        return candidates[0]?.token || null;
    }

    function describeGraphTokens() {
        return [...state.tokens.values()]
            .filter(tokenIsCurrent)
            .filter(x => isGraphAudience(x.aud))
            .map(x => ({
                source: x.source,
                scopes: [...x.scopes].sort(),
                roles: [...x.roles].sort(),
            }));
    }

    function extractAuthorization(headers) {
        try {
            if (!headers) return null;
            if (headers instanceof Headers) return headers.get('Authorization');
            if (Array.isArray(headers)) {
                const hit = headers.find(([k]) => String(k).toLowerCase() === 'authorization');
                return hit?.[1] || null;
            }
            for (const [k, v] of Object.entries(headers)) {
                if (k.toLowerCase() === 'authorization') return v;
            }
        } catch { /* ignored */ }
        return null;
    }

    // ---------------------------------------------------------------------
    // Network interception
    // ---------------------------------------------------------------------

    function requestUrl(input) {
        try {
            if (typeof input === 'string') return input;
            if (input instanceof URL) return input.href;
            if (typeof Request !== 'undefined' && input instanceof Request) return input.url;
            if (input && typeof input.url === 'string') return input.url;
            if (input && typeof input.href === 'string') return input.href;
            const text = String(input ?? '');
            return /^https?:\/\//i.test(text) ? text : '';
        } catch {
            return '';
        }
    }

    function consumeAggregatedDrivers(payload) {
        const list = payload?.aggregatedDriverSettingsCollection;
        if (!Array.isArray(list)) return;

        let added = 0;
        for (const driver of list) {
            if (!driver?.driverId) continue;
            state.driverById.set(driver.driverId, driver);
            state.driverByKey.set(driverKey(driver), driver);
            added++;
        }
        log(`Captured ${added} aggregated driver records.`);
        scheduleInject();
    }

    async function inspectFetchResponse(url, response) {
        if (!String(url).includes('/update-management/v2/DriverUpdate/aggregatedDriversList')) return;
        try {
            consumeAggregatedDrivers(await response.clone().json());
        } catch (e) {
            warn('Could not parse aggregatedDriversList response', e);
        }
    }

    function patchFetch() {
        if (!state.originalFetch || window.fetch.__tmDriverImpactPatched) return;
        const original = state.originalFetch;

        const wrapped = async function(input, init = undefined) {
            const url = requestUrl(input);
            const auth = extractAuthorization(init?.headers) ||
                ((typeof Request !== 'undefined' && input instanceof Request) ? input.headers.get('Authorization') : null);
            if (auth) addToken(auth, `fetch ${url}`);

            const response = await original(input, init);
            inspectFetchResponse(url, response).catch(() => {});
            return response;
        };
        wrapped.__tmDriverImpactPatched = true;
        window.fetch = wrapped;
    }

    function patchXhr() {
        const proto = XMLHttpRequest.prototype;
        if (proto.__tmDriverImpactPatched) return;
        proto.__tmDriverImpactPatched = true;

        const nativeOpen = proto.open;
        const nativeSetRequestHeader = proto.setRequestHeader;
        const nativeSend = proto.send;

        proto.open = function(method, url, ...rest) {
            this.__tmDiUrl = String(url || '');
            this.__tmDiMethod = String(method || 'GET');
            this.__tmDiHeaders = {};
            return nativeOpen.call(this, method, url, ...rest);
        };

        proto.setRequestHeader = function(name, value) {
            try {
                this.__tmDiHeaders[String(name).toLowerCase()] = String(value);
                if (String(name).toLowerCase() === 'authorization') {
                    addToken(String(value), `xhr ${this.__tmDiUrl || ''}`);
                }
            } catch { /* ignored */ }
            return nativeSetRequestHeader.call(this, name, value);
        };

        proto.send = function(...args) {
            if (!this.__tmDiListenerAdded) {
                this.__tmDiListenerAdded = true;
                this.addEventListener('loadend', () => {
                    const url = this.__tmDiUrl || '';
                    if (!url.includes('/update-management/v2/DriverUpdate/aggregatedDriversList')) return;
                    try {
                        if (typeof this.responseText === 'string' && this.responseText) {
                            consumeAggregatedDrivers(JSON.parse(this.responseText));
                        }
                    } catch (e) {
                        warn('Could not parse XHR aggregatedDriversList response', e);
                    }
                });
            }
            return nativeSend.apply(this, args);
        };
    }

    function isJwtLike(value) {
        return typeof value === 'string' && /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}$/.test(value.trim());
    }

    function scanValueForJwt(value, source = 'unknown', context = null, depth = 0) {
        const ctx = context || { seen: new WeakSet(), nodes: 0, tokens: 0 };
        if (ctx.nodes++ > 500 || depth > 8 || value == null) return ctx;

        if (typeof value === 'string') {
            const text = value.trim();
            if (!text) return ctx;

            if (isJwtLike(text)) {
                const before = state.tokens.size;
                addToken(text, source);
                if (state.tokens.size > before) ctx.tokens++;
                return ctx;
            }

            // MSAL values and portal messages often contain a JSON object whose
            // "secret" / "accessToken" property is the actual access token.
            if ((text.startsWith('{') && text.endsWith('}')) ||
                (text.startsWith('[') && text.endsWith(']'))) {
                try {
                    scanValueForJwt(JSON.parse(text), `${source}:json`, ctx, depth + 1);
                } catch { /* not JSON */ }
            }

            // Also catch a token embedded in a larger message/string.
            const matches = text.match(/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{8,}/g) || [];
            for (const token of matches) {
                const before = state.tokens.size;
                addToken(token, source);
                if (state.tokens.size > before) ctx.tokens++;
            }
            return ctx;
        }

        if (typeof value !== 'object') return ctx;
        try {
            if (ctx.seen.has(value)) return ctx;
            ctx.seen.add(value);
        } catch { return ctx; }

        if (Array.isArray(value)) {
            for (let i = 0; i < Math.min(value.length, 200); i++) {
                scanValueForJwt(value[i], `${source}[${i}]`, ctx, depth + 1);
            }
            return ctx;
        }

        // Avoid traversing DOM / Window / Request objects. We only need ordinary
        // data objects used by MSAL and portal message payloads.
        let proto = null;
        try { proto = Object.getPrototypeOf(value); } catch { return ctx; }
        if (proto && proto !== Object.prototype && proto !== null) return ctx;

        const priorityKeys = ['secret', 'accessToken', 'access_token', 'token', 'idToken', 'id_token'];
        for (const key of priorityKeys) {
            try {
                if (typeof value[key] === 'string') {
                    scanValueForJwt(value[key], `${source}.${key}`, ctx, depth + 1);
                }
            } catch { /* ignored */ }
        }

        let entries = [];
        try { entries = Object.entries(value).slice(0, 200); } catch { return ctx; }
        for (const [key, child] of entries) {
            if (priorityKeys.includes(key)) continue;
            scanValueForJwt(child, `${source}.${key}`, ctx, depth + 1);
        }
        return ctx;
    }

    function scanStorageObject(storage, storageName) {
        let found = 0;
        try {
            for (let i = 0; i < storage.length; i++) {
                const key = storage.key(i);
                if (!key) continue;
                const value = storage.getItem(key);
                if (!value) continue;

                // Fast path for MSAL access-token cache entries. This was the
                // decisive path in the earlier working Intune userscripts.
                try {
                    const parsed = JSON.parse(value);
                    if (parsed && typeof parsed === 'object') {
                        const credentialType = String(parsed.credentialType || parsed.credential_type || '').toLowerCase();
                        if (credentialType === 'accesstoken' && typeof parsed.secret === 'string') {
                            const before = state.tokens.size;
                            addToken(parsed.secret, `${storageName}:MSAL:${key}`);
                            if (state.tokens.size > before) found++;
                        }
                        const ctx = scanValueForJwt(parsed, `${storageName}:${key}`);
                        found += ctx.tokens;
                        continue;
                    }
                } catch { /* raw/non-JSON cache value */ }

                const ctx = scanValueForJwt(value, `${storageName}:${key}`);
                found += ctx.tokens;
            }
        } catch (e) {
            log(`Could not scan ${storageName}`, e);
        }
        return found;
    }

    function scanAuthBootstrapState() {
        let found = 0;
        const names = [
            'authBootstrapState', '__authBootstrapState', '_authBootstrapState',
            'authBootstrap', '__authBootstrap', 'bootstrapState'
        ];
        for (const name of names) {
            try {
                if (!(name in window)) continue;
                const ctx = scanValueForJwt(window[name], `window.${name}`);
                found += ctx.tokens;
            } catch { /* cross-realm / getter */ }
        }
        return found;
    }

    function scanStorageForJwt() {
        let found = 0;
        try { found += scanStorageObject(sessionStorage, 'sessionStorage'); } catch { /* ignored */ }
        try { found += scanStorageObject(localStorage, 'localStorage'); } catch { /* ignored */ }
        found += scanAuthBootstrapState();
        if (found) log(`${found} new token candidate(s) discovered from MSAL/storage/bootstrap state.`);
        return found;
    }

    function postMessageSafe(target, message) {
        try { target?.postMessage(message, '*'); } catch { /* ignored */ }
    }

    function forEachChildFrame(callback) {
        try {
            for (const frame of document.querySelectorAll('iframe')) {
                try {
                    if (frame.contentWindow) callback(frame.contentWindow);
                } catch { /* ignored */ }
            }
        } catch { /* ignored */ }
    }

    function broadcastToken(token, source = '') {
        const message = {
            signature: SCRIPT.id,
            type: 'token',
            token,
            source,
            senderHref: location.href,
        };

        if (window !== window.top) {
            // Send directly to the top-level Intune shell as well as the immediate
            // parent. Direct-to-top prevents a missing intermediate bridge.
            postMessageSafe(window.top, message);
            if (window.parent !== window.top) postMessageSafe(window.parent, message);
        } else {
            // Root token: push it down immediately. This is the v0.2 regression fix.
            forEachChildFrame(frameWindow => postMessageSafe(frameWindow, { ...message, relayedByRoot: true }));
        }
    }

    function sendKnownTokensTo(target, reason = 'sync') {
        for (const candidate of state.tokens.values()) {
            if (!tokenIsCurrent(candidate) || !isGraphAudience(candidate.aud)) continue;
            postMessageSafe(target, {
                signature: SCRIPT.id,
                type: 'token',
                token: candidate.token,
                source: `${reason}:${candidate.source || 'local'}`,
                relayedByRoot: window === window.top,
            });
        }
    }

    let tokenWarmupFrame = null;
    function createIntuneTokenWarmupFrame() {
        if (window !== window.top || tokenWarmupFrame || !document.documentElement) return;
        if (getGraphToken(['DeviceManagementManagedDevices.Read.All'])) return;

        // Same method that solved the token problem in the earlier Intune scripts:
        // load an Intune Device blade invisibly so the portal itself acquires a
        // DeviceManagement token. No separate sign-in is performed.
        const frame = document.createElement('iframe');
        frame.id = `${SCRIPT.id}-token-warmup`;
        frame.setAttribute('aria-hidden', 'true');
        frame.tabIndex = -1;
        frame.style.cssText = 'position:fixed!important;width:1px!important;height:1px!important;left:-10000px!important;top:-10000px!important;opacity:0!important;pointer-events:none!important;border:0!important;';
        frame.src = 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview';
        (document.body || document.documentElement).appendChild(frame);
        tokenWarmupFrame = frame;
        log('Started hidden Intune Devices token warm-up frame.');

        setTimeout(() => {
            try { frame.remove(); } catch { /* ignored */ }
            if (tokenWarmupFrame === frame) tokenWarmupFrame = null;
        }, 20000);
    }

    function requestIntuneTokenSync({ warmup = false } = {}) {
        scanStorageForJwt();
        const message = { signature: SCRIPT.id, type: 'request-token-sync', requesterHref: location.href };

        if (window === window.top) {
            forEachChildFrame(frameWindow => postMessageSafe(frameWindow, message));
            if (warmup) createIntuneTokenWarmupFrame();
        } else {
            postMessageSafe(window.top, message);
            postMessageSafe(window.parent, message);
            if (warmup) postMessageSafe(window.top, { signature: SCRIPT.id, type: 'request-token-warmup' });
        }
    }

    function patchPortalMessageChannels() {
        // Tokens can cross Azure Portal boundaries inside postMessage / MessagePort
        // payloads. Capture them at document-start, as in the earlier working script.
        try {
            if (window.postMessage && !window.postMessage.__tmDriverImpactPatched) {
                const native = window.postMessage;
                const wrapped = function(message, ...rest) {
                    try { scanValueForJwt(message, 'window.postMessage:out'); } catch { /* ignored */ }
                    return Reflect.apply(native, this, [message, ...rest]);
                };
                wrapped.__tmDriverImpactPatched = true;
                window.postMessage = wrapped;
            }
        } catch (e) { log('Could not hook window.postMessage', e); }

        try {
            const proto = window.MessagePort?.prototype;
            if (proto?.postMessage && !proto.postMessage.__tmDriverImpactPatched) {
                const native = proto.postMessage;
                const wrapped = function(message, ...rest) {
                    try { scanValueForJwt(message, 'MessagePort.postMessage:out'); } catch { /* ignored */ }
                    return Reflect.apply(native, this, [message, ...rest]);
                };
                wrapped.__tmDriverImpactPatched = true;
                proto.postMessage = wrapped;
            }
        } catch (e) { log('Could not hook MessagePort.postMessage', e); }

        try {
            const proto = window.BroadcastChannel?.prototype;
            if (proto?.postMessage && !proto.postMessage.__tmDriverImpactPatched) {
                const native = proto.postMessage;
                const wrapped = function(message, ...rest) {
                    try { scanValueForJwt(message, 'BroadcastChannel.postMessage:out'); } catch { /* ignored */ }
                    return Reflect.apply(native, this, [message, ...rest]);
                };
                wrapped.__tmDriverImpactPatched = true;
                proto.postMessage = wrapped;
            }
        } catch (e) { log('Could not hook BroadcastChannel.postMessage', e); }
    }

    function installTokenBridge() {
        patchPortalMessageChannels();

        window.addEventListener('message', event => {
            const data = event.data;

            // First inspect all portal messages, not just our own bridge messages.
            try { scanValueForJwt(data, 'window.message:in'); } catch { /* ignored */ }

            if (!data || data.signature !== SCRIPT.id) return;

            if (data.type === 'token' && data.token) {
                addToken(data.token, `bridge:${data.source || 'frame'}`, false);

                // Root relays a child token to all sibling ReactViews.
                if (window === window.top && !data.relayedByRoot) {
                    const relayed = { ...data, relayedByRoot: true };
                    forEachChildFrame(frameWindow => postMessageSafe(frameWindow, relayed));
                }
                return;
            }

            if (data.type === 'request-token-sync') {
                scanStorageForJwt();
                if (event.source) sendKnownTokensTo(event.source, 'requested-sync');
                if (window === window.top) {
                    // Ask all other ReactViews too; a DeviceManagement token may live
                    // in a frame other than the one containing the driver table.
                    forEachChildFrame(frameWindow => {
                        if (frameWindow !== event.source) postMessageSafe(frameWindow, data);
                    });
                }
                return;
            }

            if (data.type === 'request-token-warmup' && window === window.top) {
                createIntuneTokenWarmupFrame();
            }
        }, true);

        // Tell the shell that this frame exists. If the shell already has a token it
        // can now push it into this ReactView even when no new Graph request occurs.
        if (window !== window.top) {
            postMessageSafe(window.top, { signature: SCRIPT.id, type: 'request-token-sync', requesterHref: location.href });
        }
    }

    async function waitForIntuneGraphToken(requiredPermissions = ['DeviceManagementManagedDevices.Read.All'], timeoutMs = 12000) {
        let token = getGraphToken(requiredPermissions);
        if (token) return token;

        requestIntuneTokenSync({ warmup: false });
        const started = Date.now();
        let warmupRequested = false;

        while (Date.now() - started < timeoutMs) {
            scanStorageForJwt();
            token = getGraphToken(requiredPermissions);
            if (token) return token;

            if (!warmupRequested && Date.now() - started >= 1200) {
                warmupRequested = true;
                requestIntuneTokenSync({ warmup: true });
            }

            await sleep(350);
        }
        return getGraphToken(requiredPermissions);
    }

    // ---------------------------------------------------------------------
    // Graph API
    // ---------------------------------------------------------------------

    class GraphPermissionError extends Error {
        constructor(permission, detail = '') {
            super(`No Microsoft Graph token with ${permission} is available.${detail ? ` ${detail}` : ''}`);
            this.name = 'GraphPermissionError';
            this.permission = permission;
        }
    }

    async function graphRequest(url, {
        method = 'GET',
        body = undefined,
        permissions = [],
        signal = undefined,
    } = {}) {
        const token = getGraphToken(permissions);
        if (!token) throw new GraphPermissionError(permissions.join(' + ') || 'the required permissions');

        const absoluteUrl = url.startsWith('http') ? url : `${SCRIPT.graph}${url}`;
        const response = await state.originalFetch(absoluteUrl, {
            method,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
                ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
            },
            body: body !== undefined ? JSON.stringify(body) : undefined,
            signal,
        });

        let data = null;
        if (response.status !== 204) {
            const text = await response.text();
            try { data = text ? JSON.parse(text) : null; } catch { data = text; }
        }

        if (!response.ok) {
            const detail = data?.error?.message || data?.message || `${response.status} ${response.statusText}`;
            const code = data?.error?.code || data?.code || '';
            let path = absoluteUrl;
            try {
                const u = new URL(absoluteUrl);
                path = `${u.pathname}${u.search || ''}`;
            } catch { /* keep absolute URL */ }
            const statusText = `${response.status}${code ? ` / ${code}` : ''}`;
            const error = new Error(`Graph ${method} ${path} failed (${statusText}): ${detail}`);
            error.status = response.status;
            error.code = code;
            error.data = data;
            error.url = absoluteUrl;
            const retryAfter = Number(response.headers?.get?.('Retry-After') || 0);
            error.retryAfterMs = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 0;
            throw error;
        }
        return data;
    }

    async function graphRequestRetry(url, options = {}, {
        attempts = 5,
        retryStatuses = [429, 500, 502, 503, 504],
        baseDelayMs = 500,
        onRetry = null,
    } = {}) {
        let lastError = null;
        for (let attempt = 1; attempt <= attempts; attempt++) {
            try {
                return await graphRequest(url, options);
            } catch (e) {
                lastError = e;
                if (attempt >= attempts || !retryStatuses.includes(Number(e?.status))) throw e;
                const delay = Math.max(Number(e?.retryAfterMs || 0), baseDelayMs * attempt);
                onRetry?.(e, attempt, delay);
                await sleep(delay);
            }
        }
        throw lastError;
    }

    async function graphPaged(url, options, onPage = null) {
        const all = [];
        let next = url;
        let page = 0;
        while (next) {
            const data = await graphRequest(next, options);
            const values = Array.isArray(data?.value) ? data.value : [];
            all.push(...values);
            page++;
            onPage?.({ page, values, total: all.length });
            next = data?.['@odata.nextLink'] || null;
        }
        return all;
    }

    async function graphBatch(requests, permissions, signal) {
        if (!requests.length) return [];
        const result = await graphRequest('/beta/$batch', {
            method: 'POST',
            permissions,
            signal,
            body: { requests },
        });
        return result?.responses || [];
    }

    async function listDeploymentAudiences(signal, progress) {
        progress?.('Discovering Windows Update deployment audiences...');
        return graphPaged('/beta/admin/windows/updates/deploymentAudiences', {
            permissions: ['WindowsUpdates.Read.All'],
            signal,
        }, x => progress?.(`Discovering deployment audiences... ${x.total}`));
    }

    async function getMatchedDevicesAcrossAudiences(catalogEntryId, signal, progress) {
        const audiences = await listDeploymentAudiences(signal, progress);
        const devices = new Map();
        let checked = 0;

        const addValues = (audienceId, body) => {
            for (const item of body?.value || []) {
                if (!item?.deviceId) continue;
                let d = devices.get(item.deviceId);
                if (!d) {
                    d = {
                        entraDeviceId: item.deviceId,
                        recommendedBy: new Set(),
                        audienceIds: new Set(),
                    };
                    devices.set(item.deviceId, d);
                }
                d.audienceIds.add(audienceId);
                for (const r of item.recommendedBy || []) d.recommendedBy.add(r);
            }
        };

        const continuation = [];
        for (const group of chunk(audiences, SCRIPT.maxBatch)) {
            if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
            const requests = group.map((aud, idx) => ({
                id: String(idx + 1),
                method: 'GET',
                url: `/admin/windows/updates/deploymentAudiences/${encodeURIComponent(aud.id)}/applicableContent/${encodeURIComponent(catalogEntryId)}/matchedDevices`,
            }));
            const responses = await graphBatch(requests, ['WindowsUpdates.Read.All'], signal);

            const audienceByRequestId = new Map(group.map((aud, idx) => [String(idx + 1), aud]));
            responses.forEach(r => {
                const aud = audienceByRequestId.get(String(r.id));
                if (!aud) return;
                if (r.status >= 200 && r.status < 300) {
                    addValues(aud.id, r.body);
                    const next = r.body?.['@odata.nextLink'];
                    if (next) continuation.push({ audienceId: aud.id, url: next });
                } else if (![400, 404].includes(r.status)) {
                    log('Audience applicable-content lookup returned', r.status, aud.id, r.body);
                }
            });

            checked += group.length;
            progress?.(`Checking driver applicability... ${checked}/${audiences.length} audiences, ${devices.size} unique devices`);
        }

        // Follow continuation links. These normally exist only for audiences with >100 matches.
        for (let i = 0; i < continuation.length; i++) {
            const item = continuation[i];
            let next = item.url;
            while (next) {
                const body = await graphRequest(next, {
                    permissions: ['WindowsUpdates.Read.All'],
                    signal,
                });
                addValues(item.audienceId, body);
                next = body?.['@odata.nextLink'] || null;
                progress?.(`Loading matched devices... ${devices.size} unique devices`);
            }
        }

        return [...devices.values()].map(d => ({
            ...d,
            recommendedBy: [...d.recommendedBy],
            audienceIds: [...d.audienceIds],
        }));
    }

    async function resolveManagedDeviceBatch(deviceIds, signal, progress) {
        const resolved = new Map();
        let done = 0;

        for (const ids of chunk(deviceIds, SCRIPT.maxBatch)) {
            const requests = ids.map((id, idx) => ({
                id: String(idx + 1),
                method: 'GET',
                url: `/deviceManagement/managedDevices?$filter=${encodeURIComponent(`azureADDeviceId eq '${id}'`)}&$select=id,deviceName,azureADDeviceId,manufacturer,model,serialNumber,operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,complianceState,managementAgent`,
            }));
            const responses = await graphBatch(requests, ['DeviceManagementManagedDevices.Read.All'], signal);
            const idByRequestId = new Map(ids.map((id, idx) => [String(idx + 1), id]));
            responses.forEach(r => {
                const deviceId = idByRequestId.get(String(r.id));
                if (!deviceId) return;
                if (r.status >= 200 && r.status < 300) {
                    const item = r.body?.value?.[0];
                    if (item) resolved.set(deviceId.toLowerCase(), item);
                }
            });
            done += ids.length;
            progress?.(`Resolving Intune device metadata... ${done}/${deviceIds.length}`);
        }
        return resolved;
    }

    async function resolveManagedDeviceInventory(deviceIds, signal, progress) {
        const wanted = new Set(deviceIds.map(x => x.toLowerCase()));
        const resolved = new Map();
        let next = '/beta/deviceManagement/managedDevices?$select=id,deviceName,azureADDeviceId,manufacturer,model,serialNumber,operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,complianceState,managementAgent&$top=999';
        let scanned = 0;

        while (next && resolved.size < wanted.size) {
            const body = await graphRequest(next, {
                permissions: ['DeviceManagementManagedDevices.Read.All'],
                signal,
            });
            const rows = body?.value || [];
            scanned += rows.length;
            for (const item of rows) {
                const id = String(item.azureADDeviceId || '').toLowerCase();
                if (id && wanted.has(id)) resolved.set(id, item);
            }
            progress?.(`Resolving Intune device metadata... ${resolved.size}/${wanted.size} matched (${scanned} inventory rows scanned)`);
            next = body?.['@odata.nextLink'] || null;
        }
        return resolved;
    }

    async function resolveManagedDevices(deviceIds, signal, progress) {
        if (!deviceIds.length) return new Map();
        // Small result sets are faster via filtered $batch requests. Large sets are
        // usually faster by reading the managed-device inventory once and indexing it.
        if (deviceIds.length <= 200) {
            return resolveManagedDeviceBatch(deviceIds, signal, progress);
        }
        try {
            return await resolveManagedDeviceInventory(deviceIds, signal, progress);
        } catch (e) {
            warn('Bulk managed-device enumeration failed; falling back to batch lookups.', e);
            return resolveManagedDeviceBatch(deviceIds, signal, progress);
        }
    }

    async function resolveManagedDevicesFromReport(reportRows, signal, progress) {
        const resolved = new Map();
        const direct = [];
        const seenIntune = new Set();
        const allAadIds = [...new Set(reportRows
            .map(row => String(row.entraDeviceId || '').toLowerCase())
            .filter(Boolean))];

        for (const row of reportRows) {
            const intuneId = String(row.intuneDeviceId || '').toLowerCase();
            const aadId = String(row.entraDeviceId || '').toLowerCase();
            if (intuneId && !seenIntune.has(intuneId)) {
                seenIntune.add(intuneId);
                direct.push({ intuneId, aadId });
            }
        }

        // First use the Intune managed-device ids already returned by the Driver
        // Update report. Run batches sequentially. Some tenants return a generic
        // service error when several /$batch calls are executed concurrently.
        let batchFailed = false;
        let done = 0;
        for (const group of chunk(direct, SCRIPT.maxBatch)) {
            if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
            try {
                const requests = group.map((item, idx) => ({
                    id: String(idx + 1),
                    method: 'GET',
                    url: `/deviceManagement/managedDevices/${encodeURIComponent(item.intuneId)}?$select=id,deviceName,azureADDeviceId,manufacturer,model,serialNumber,operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,complianceState,managementAgent`,
                }));
                const responses = await graphBatch(requests, ['DeviceManagementManagedDevices.Read.All'], signal);
                const itemById = new Map(group.map((item, idx) => [String(idx + 1), item]));
                for (const response of responses) {
                    const item = itemById.get(String(response.id));
                    if (!item || response.status < 200 || response.status >= 300 || !response.body) continue;
                    const md = response.body;
                    const key = String(md.azureADDeviceId || item.aadId || '').toLowerCase();
                    if (key) resolved.set(key, md);
                }
                done += group.length;
                progress?.(`Resolving Intune hardware metadata... ${done}/${direct.length}`);
            } catch (e) {
                batchFailed = true;
                warn('Managed-device batch lookup failed; switching to inventory fallback.', e);
                break;
            }
        }

        const unresolvedAad = allAadIds.filter(id => !resolved.has(id));
        if (!unresolvedAad.length) return resolved;

        // A tenant-wide managedDevices enumeration is slower, but it avoids the
        // Graph JSON batching path entirely and is very reliable as a fallback.
        try {
            const inventory = await resolveManagedDeviceInventory(
                unresolvedAad,
                signal,
                text => progress?.(`${batchFailed ? 'Batch lookup failed. ' : ''}${text}`)
            );
            for (const [key, value] of inventory) resolved.set(key, value);
            return resolved;
        } catch (e) {
            warn('Managed-device inventory fallback failed.', e);
        }

        // Last resort: filtered batch queries by Entra device id. If this also
        // fails, let the caller keep the Driver Update report data without the
        // additional hardware metadata instead of losing the whole result set.
        try {
            const fallback = await resolveManagedDeviceBatch(unresolvedAad, signal, text => progress?.(text));
            for (const [key, value] of fallback) resolved.set(key, value);
        } catch (e) {
            warn('Final managed-device lookup fallback failed.', e);
        }
        return resolved;
    }

    async function resolveEntraDevicesFallback(deviceIds, signal, progress) {
        const token = getGraphToken(['Device.Read.All']);
        if (!token) return new Map();

        const resolved = new Map();
        let done = 0;
        for (const ids of chunk(deviceIds, SCRIPT.maxBatch)) {
            const requests = ids.map((id, idx) => ({
                id: String(idx + 1),
                method: 'GET',
                url: `/devices(deviceId='${encodeURIComponent(id)}')?$select=id,deviceId,displayName,manufacturer,model,operatingSystem,operatingSystemVersion`,
            }));
            const responses = await graphBatch(requests, ['Device.Read.All'], signal);
            const idByRequestId = new Map(ids.map((id, idx) => [String(idx + 1), id]));
            responses.forEach(r => {
                const deviceId = idByRequestId.get(String(r.id));
                if (!deviceId) return;
                if (r.status >= 200 && r.status < 300 && r.body) {
                    resolved.set(deviceId.toLowerCase(), r.body);
                }
            });
            done += ids.length;
            progress?.(`Resolving Entra fallback metadata... ${done}/${deviceIds.length}`);
        }
        return resolved;
    }

    // ---------------------------------------------------------------------
    // Intune Driver Update Report
    // ---------------------------------------------------------------------

    const DRIVER_REPORT_ID = 'DriverUpdateDeviceStatusByDriver_00000000-0000-0000-0000-000000000001';
    const DRIVER_REPORT_SELECT = [
        'DeviceName', 'UPN', 'DeviceId', 'AadDeviceId', 'CurrentDeviceUpdateSubstateTime',
        'PolicyName', 'CurrentDeviceUpdateState', 'CurrentDeviceUpdateSubstate',
        'AggregateState', 'HighestPriorityAlertSubType', 'LastWUScanTime',
    ];

    function reportValuesToObjects(payload) {
        const schema = Array.isArray(payload?.Schema) ? payload.Schema.map(x => x.Column) : [];
        return (payload?.Values || []).map(values => {
            const row = {};
            schema.forEach((name, idx) => { row[name] = values[idx]; });
            return row;
        });
    }

    function utf8Base64(value) {
        const bytes = new TextEncoder().encode(String(value ?? ''));
        let binary = '';
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary);
    }

    function odataLiteral(value) {
        return String(value ?? '').replaceAll("'", "''");
    }

    async function findDriverInReportInventory(driver, signal, progress) {
        const wantedName = normalizeText(driver.name).toLocaleLowerCase();
        const wantedVersion = normalizeText(driver.driverVersion).toLocaleLowerCase();
        const wantedManufacturer = normalizeText(driver.manufacturer).toLocaleLowerCase();
        const wantedManufacturerCanonical = canonicalManufacturer(driver.manufacturer);
        const wantedNameCanonical = canonicalDriverName(driver.name, driver.driverVersion);
        const top = 100;
        let skip = 0;
        let total = Infinity;
        const allCandidates = [];

        progress?.('Driver metadata was not captured; resolving CatalogEntryId from the Intune Driver Update inventory...');

        while (skip < total) {
            const payload = await graphRequest('/beta/deviceManagement/reports/getReportFilters', {
                method: 'POST',
                permissions: ['DeviceManagementManagedDevices.Read.All'],
                signal,
                body: {
                    name: 'DriverUpdateInventory',
                    select: null,
                    skip,
                    top,
                    filter: '',
                    orderBy: null,
                },
            });
            total = Number(payload?.TotalRowCount ?? 0);
            const rows = reportValuesToObjects(payload);

            for (const x of rows) {
                const rowVersion = normalizeText(x.Version).toLocaleLowerCase();
                if (!wantedVersion || rowVersion !== wantedVersion) continue;

                const rowManufacturer = normalizeText(x.Manufacturer).toLocaleLowerCase();
                const rowManufacturerCanonical = canonicalManufacturer(x.Manufacturer);
                const manufacturerMatches = !wantedManufacturer ||
                    rowManufacturer === wantedManufacturer ||
                    (wantedManufacturerCanonical && rowManufacturerCanonical === wantedManufacturerCanonical) ||
                    (wantedManufacturerCanonical && rowManufacturerCanonical &&
                        (rowManufacturerCanonical.includes(wantedManufacturerCanonical) ||
                         wantedManufacturerCanonical.includes(rowManufacturerCanonical)));

                if (manufacturerMatches) allCandidates.push(x);
            }

            // Resolve immediately when this page gives us an exact textual or
            // canonical name match. Canonical matching deliberately removes
            // the version plus generic "Driver Update" wording used by some
            // Intune views but not others.
            const pageCandidates = allCandidates.filter(x => !x.__tmChecked);
            for (const x of pageCandidates) x.__tmChecked = true;
            const exact = pageCandidates.find(x => normalizeText(x.DriverName).toLocaleLowerCase() === wantedName);
            const canonical = pageCandidates.find(x =>
                wantedNameCanonical && canonicalDriverName(x.DriverName, x.Version) === wantedNameCanonical
            );
            const immediate = exact || canonical;
            if (immediate?.CatalogEntryId) {
                const resolved = {
                    ...driver,
                    driverId: immediate.CatalogEntryId,
                    name: driver.name || immediate.DriverName,
                    driverVersion: driver.driverVersion || immediate.Version,
                    manufacturer: driver.manufacturer || immediate.Manufacturer,
                    driverClass: driver.driverClass || immediate.DriverClass,
                };
                state.driverById.set(resolved.driverId, resolved);
                state.driverByKey.set(driverKey(resolved), resolved);
                return resolved;
            }

            skip += top;
            progress?.(`Resolving CatalogEntryId... ${Math.min(skip, total)}/${total || '?'} inventory rows checked`);
        }

        // Version + manufacturer is normally unique even when the display name
        // differs between Autopatch and the report picker.
        if (allCandidates.length === 1 && allCandidates[0]?.CatalogEntryId) {
            const hit = allCandidates[0];
            const resolved = {
                ...driver,
                driverId: hit.CatalogEntryId,
                name: driver.name || hit.DriverName,
                driverVersion: driver.driverVersion || hit.Version,
                manufacturer: driver.manufacturer || hit.Manufacturer,
                driverClass: driver.driverClass || hit.DriverClass,
            };
            state.driverById.set(resolved.driverId, resolved);
            state.driverByKey.set(driverKey(resolved), resolved);
            return resolved;
        }

        const examples = allCandidates.slice(0, 5).map(x =>
            `${x.DriverName} | ${x.Manufacturer} | ${x.Version} | ${x.DriverClass || ''}`
        );
        const detail = allCandidates.length
            ? ` ${allCandidates.length} inventory candidates matched version/manufacturer: ${examples.join(' ; ')}`
            : ' No inventory row matched the normalized version/manufacturer.';
        throw new Error(`Could not resolve CatalogEntryId for ${driver.name} [version=${driver.driverVersion}, manufacturer=${driver.manufacturer}].${detail}`);
    }

    async function ensureDriverMetadata(driver, signal, progress) {
        if (/^[a-f0-9]{64}_[0-9a-f-]{36}$/i.test(String(driver?.driverId || ''))) return driver;
        return findDriverInReportInventory(driver, signal, progress);
    }

    function driverReportFilter(catalogEntryId) {
        const id = odataLiteral(catalogEntryId);
        // Mirror the portal request. The report UI currently emits the CatalogEntryId filter twice.
        return `(CatalogEntryId eq '${id}') and (CatalogEntryId eq '${id}')`;
    }

    function driverReportMetadata(driver) {
        return `CatalogEntryId=>filterPicker=${utf8Base64(driver.name || driver.driverVersion || 'Driver')}`;
    }

    function reportConfigPath() {
        return `/beta/deviceManagement/reports/cachedReportConfigurations('${DRIVER_REPORT_ID}')`;
    }

    function normalizeFilterExpression(value) {
        return normalizeText(value).replaceAll('(', '').replaceAll(')', '').toLowerCase();
    }

    async function getDriverReportConfig(signal) {
        try {
            return await graphRequest(reportConfigPath(), {
                permissions: ['DeviceManagementManagedDevices.Read.All'],
                signal,
            });
        } catch (e) {
            if (e?.status === 404) return null;
            throw e;
        }
    }

    async function createDriverReportConfig(driver, signal) {
        const filter = driverReportFilter(driver.driverId);
        return graphRequest('/beta/deviceManagement/reports/cachedReportConfigurations', {
            method: 'POST',
            permissions: ['DeviceManagementManagedDevices.ReadWrite.All'],
            signal,
            body: {
                id: DRIVER_REPORT_ID,
                filter,
                orderBy: [],
                select: DRIVER_REPORT_SELECT,
                search: '',
                metadata: driverReportMetadata(driver),
            },
        });
    }

    async function deleteDriverReportConfig(signal) {
        try {
            await graphRequest(reportConfigPath(), {
                method: 'DELETE',
                permissions: ['DeviceManagementManagedDevices.ReadWrite.All'],
                signal,
            });
        } catch (e) {
            // Deleting an already-expired/non-existing cache is harmless.
            if (e?.status !== 404) throw e;
        }
    }

    async function recreateDriverReportConfig(driver, signal, progress) {
        progress?.('Recreating Intune Driver Update report cache for this driver...');
        await deleteDriverReportConfig(signal);

        // The service can need a short moment until a DELETE is visible to the
        // following POST. Retry conflict/transient responses a few times.
        let lastError = null;
        for (let attempt = 0; attempt < 5; attempt++) {
            if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
            try {
                return await createDriverReportConfig(driver, signal);
            } catch (e) {
                lastError = e;
                if (![409, 429, 500, 502, 503, 504].includes(Number(e?.status))) throw e;
                await sleep(350 * (attempt + 1));
            }
        }
        throw lastError || new Error('Could not recreate the Intune Driver Update report cache.');
    }

    async function ensureDriverReportConfig(driver, signal, progress) {
        const desired = normalizeFilterExpression(driverReportFilter(driver.driverId));
        let config = await getDriverReportConfig(signal);

        if (!config) {
            progress?.('Preparing Intune Driver Update report cache...');
            await createDriverReportConfig(driver, signal);
        } else if (normalizeFilterExpression(config.filter) !== desired) {
            // Intune cached-report filters are immutable in practice. Graph exposes
            // PATCH for the resource, but the service rejects changing Filter on an
            // existing cached report configuration. The native portal therefore
            // needs a fresh cache for a different CatalogEntryId.
            await recreateDriverReportConfig(driver, signal, progress);
        }

        // Cached reports are generated asynchronously. The portal polls this same resource.
        for (let attempt = 0; attempt < 40; attempt++) {
            if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
            config = await getDriverReportConfig(signal);
            if (!config) {
                // A transient disappearance can happen directly after recreation.
                if (attempt < 3) {
                    await sleep(500);
                    continue;
                }
                throw new Error('The Intune Driver Update report cache disappeared while it was being generated.');
            }

            const actual = normalizeFilterExpression(config.filter);
            if (actual !== desired) {
                if (attempt <= 1) {
                    await recreateDriverReportConfig(driver, signal, progress);
                    await sleep(500);
                    continue;
                }
                if (attempt > 5) {
                    throw new Error('The cached Driver Update report was recreated but still points to a different driver.');
                }
            }

            const status = String(config.status || '').toLowerCase();
            if (status === 'completed' && actual === desired) return config;
            if (status && !['inprogress', 'notstarted', 'unknown'].includes(status)) {
                throw new Error(`Driver Update report generation returned status '${config.status}'.`);
            }
            progress?.(`Generating Intune Driver Update report... ${attempt + 1}`);
            await sleep(attempt < 4 ? 1000 : 2000);
        }
        throw new Error('Timed out while waiting for the Intune Driver Update report cache.');
    }

    function reportStatePriority(row) {
        const text = `${row.aggregateState || ''} ${row.updateState || ''}`.toLowerCase();
        if (text.includes('needs attention') || text.includes('error') || text.includes('failed')) return 50;
        if (text.includes('cancel')) return 40;
        if (text.includes('installing') || text.includes('in progress')) return 30;
        if (text.includes('offering') || text.includes('pending') || text.includes('scheduled')) return 20;
        if (text.includes('installed') || text.includes('success')) return 10;
        return 0;
    }

    function normalizeDriverReportRows(rawRows) {
        const byDevice = new Map();
        for (const x of rawRows) {
            const row = {
                deviceName: x.DeviceName || '',
                userPrincipalName: x.UPN || '',
                intuneDeviceId: x.DeviceId || '',
                entraDeviceId: x.AadDeviceId || '',
                updateState: x.CurrentDeviceUpdateState_loc || String(x.CurrentDeviceUpdateState ?? ''),
                updateSubstate: x.CurrentDeviceUpdateSubstate_loc || String(x.CurrentDeviceUpdateSubstate ?? ''),
                updateSubstateTime: x.CurrentDeviceUpdateSubstateTime || '',
                aggregateState: x.AggregateState_loc || x.AggregateState || '',
                alertSubType: x.HighestPriorityAlertSubType_loc || String(x.HighestPriorityAlertSubType ?? ''),
                lastScanTime: x.LastWUScanTime || '',
                policyName: x.PolicyName || '',
            };
            const key = normalizeText(row.entraDeviceId || row.intuneDeviceId || row.deviceName).toLowerCase();
            if (!key) continue;
            const previous = byDevice.get(key);
            if (!previous) {
                row.policyNames = new Set(row.policyName ? [row.policyName] : []);
                byDevice.set(key, row);
                continue;
            }

            if (row.policyName) previous.policyNames.add(row.policyName);
            const previousPriority = reportStatePriority(previous);
            const newPriority = reportStatePriority(row);
            const previousTime = Date.parse(previous.updateSubstateTime || '') || 0;
            const newTime = Date.parse(row.updateSubstateTime || '') || 0;
            if (newPriority > previousPriority || (newPriority === previousPriority && newTime > previousTime)) {
                const policies = previous.policyNames;
                Object.assign(previous, row);
                previous.policyNames = policies;
            }
        }

        return [...byDevice.values()].map(row => ({
            ...row,
            policyName: [...row.policyNames].sort((a, b) => a.localeCompare(b)).join(' | '),
            policyCount: row.policyNames.size,
            policyNames: undefined,
        }));
    }

    async function loadDriverReportRows(driver, signal, progress) {
        await ensureDriverReportConfig(driver, signal, progress);
        const filter = driverReportFilter(driver.driverId);
        const metadata = driverReportMetadata(driver);
        // Match the native Intune portal. Its Driver Update report requests use top=50.
        const pageSize = 50;
        let skip = 0;
        let total = Infinity;
        const all = [];

        while (skip < total) {
            const payload = await graphRequestRetry('/beta/deviceManagement/reports/getCachedReport', {
                method: 'POST',
                permissions: ['DeviceManagementManagedDevices.Read.All'],
                signal,
                body: {
                    id: DRIVER_REPORT_ID,
                    top: pageSize,
                    skip,
                    search: '',
                    orderBy: [],
                    filter,
                    select: DRIVER_REPORT_SELECT,
                    metadata,
                },
            }, {
                attempts: 5,
                onRetry: (e, attempt, delay) => progress?.(
                    `Driver report page at row ${skip} returned ${e.status || 'an error'}; retry ${attempt}/4 in ${Math.round(delay / 100) / 10}s...`
                ),
            });
            total = Number(payload?.TotalRowCount ?? 0);
            const rows = reportValuesToObjects(payload);
            all.push(...rows);
            skip += rows.length;
            progress?.(`Loading Driver Update report... ${Math.min(skip, total)}/${total} rows`);
            if (!rows.length) break;
        }
        return normalizeDriverReportRows(all);
    }

    async function resolveInstallationStates(driver, signal, progress) {
        const rows = await loadDriverReportRows(driver, signal, progress);
        const map = new Map();
        for (const row of rows) {
            const key = normalizeText(row.entraDeviceId || row.intuneDeviceId || row.deviceName).toLowerCase();
            if (key) map.set(key, row);
        }
        return map;
    }

    // ---------------------------------------------------------------------
    // Data model
    // ---------------------------------------------------------------------

    function toDeviceRows(reportRows, managedMap, entraMap) {
        return reportRows.map(report => {
            const key = String(report.entraDeviceId || '').toLowerCase();
            const md = key ? managedMap.get(key) : null;
            const ed = key ? entraMap.get(key) : null;

            return {
                deviceName: md?.deviceName || report.deviceName || ed?.displayName || '',
                manufacturer: md?.manufacturer || ed?.manufacturer || '',
                model: md?.model || ed?.model || '',
                serialNumber: md?.serialNumber || '',
                operatingSystem: md?.operatingSystem || ed?.operatingSystem || '',
                osVersion: md?.osVersion || ed?.operatingSystemVersion || '',
                userPrincipalName: report.userPrincipalName || md?.userPrincipalName || '',
                complianceState: md?.complianceState || '',
                managementAgent: md?.managementAgent || '',
                lastSyncDateTime: md?.lastSyncDateTime || '',
                entraDeviceId: report.entraDeviceId || '',
                intuneDeviceId: report.intuneDeviceId || md?.id || '',
                updateState: report.updateState || '',
                updateSubstate: report.updateSubstate || '',
                updateSubstateTime: report.updateSubstateTime || '',
                aggregateState: report.aggregateState || '',
                alertSubType: report.alertSubType || '',
                lastScanTime: report.lastScanTime || '',
                policyName: report.policyName || '',
                policyCount: report.policyCount || 0,
                reportAvailable: true,
            };
        });
    }

    function aggregateModels(rows) {
        const map = new Map();
        for (const row of rows) {
            const manufacturer = normalizeText(row.manufacturer) || '(Unknown manufacturer)';
            const model = normalizeText(row.model) || '(Unknown model)';
            const key = `${manufacturer.toLowerCase()}|${model.toLowerCase()}`;
            let x = map.get(key);
            if (!x) {
                x = { manufacturer, model, count: 0, installed: 0, inProgress: 0, problems: 0, cancelled: 0 };
                map.set(key, x);
            }
            x.count++;
            const stateText = `${row.aggregateState || ''} ${row.updateState || ''}`.toLowerCase();
            if (stateText.includes('needs attention') || stateText.includes('error') || stateText.includes('failed')) x.problems++;
            else if (stateText.includes('cancel')) x.cancelled++;
            else if (stateText.includes('installed') || stateText.includes('success')) x.installed++;
            else x.inProgress++;
        }
        const total = rows.length || 1;
        return [...map.values()]
            .map(x => ({ ...x, percentage: x.count / total * 100 }))
            .sort((a, b) => b.count - a.count || a.manufacturer.localeCompare(b.manufacturer) || a.model.localeCompare(b.model));
    }

    // ---------------------------------------------------------------------
    // Portal integration
    // ---------------------------------------------------------------------

    function findDriverRecordForRow(row) {
        const name = visibleCellText(row, 'name');
        const driverVersion = visibleCellText(row, 'driverVersion');
        const manufacturer = visibleCellText(row, 'manufacturer');

        let driver = state.driverByKey.get(driverKey({ name, driverVersion, manufacturer }));
        if (driver) return driver;

        // Be tolerant of portal text changes while still requiring the same
        // version. Manufacturer/name canonicalization handles the different
        // labels used by the Autopatch list and the Driver Update report.
        const wantedManufacturer = canonicalManufacturer(manufacturer);
        const wantedName = canonicalDriverName(name, driverVersion);
        driver = [...state.driverById.values()].find(x =>
            normalizeText(x.driverVersion).toLocaleLowerCase() === driverVersion.toLocaleLowerCase() &&
            (!wantedManufacturer || canonicalManufacturer(x.manufacturer) === wantedManufacturer) &&
            (!wantedName || canonicalDriverName(x.name, x.driverVersion) === wantedName)
        );
        if (driver) return driver;

        const applicableText = visibleCellText(row, 'applicableDeviceCount');
        const applicableDeviceCount = Number((applicableText.match(/\d+/g) || []).join(''));
        return {
            name,
            driverVersion,
            manufacturer,
            applicableDeviceCount: Number.isFinite(applicableDeviceCount) ? applicableDeviceCount : null,
            driverId: '',
        };
    }

    function pageLooksLikeDriverManager() {
        if (!document.body) return false;
        return Boolean(
            document.querySelector('[data-automation-key="applicableDeviceCount"]') &&
            document.querySelector('[data-automation-key="driverVersion"]') &&
            document.querySelector('[data-automation-key="name"]')
        );
    }

    function injectButtons() {
        if (!pageLooksLikeDriverManager()) return;

        const rows = document.querySelectorAll('[data-automationid="DetailsRow"]');
        for (const row of rows) {
            const cell = row.querySelector('[data-automation-key="applicableDeviceCount"]');
            if (!cell || cell.querySelector(`.${SCRIPT.id}-view`)) continue;

            const button = document.createElement('button');
            button.type = 'button';
            button.className = `${SCRIPT.id}-view`;
            button.textContent = 'View';
            button.title = 'Show affected devices and model distribution';
            button.addEventListener('mousedown', e => e.stopPropagation());
            button.addEventListener('click', e => {
                e.preventDefault();
                e.stopPropagation();
                const driver = findDriverRecordForRow(row);
                openImpactOverlay(driver);
            });
            cell.appendChild(button);
        }
    }

    let injectTimer = 0;
    function scheduleInject() {
        clearTimeout(injectTimer);
        injectTimer = setTimeout(injectButtons, 100);
    }

    function startUiObserver() {
        const start = () => {
            if (!document.documentElement || state.uiObserver) return;
            state.uiObserver = new MutationObserver(scheduleInject);
            state.uiObserver.observe(document.documentElement, { childList: true, subtree: true });
            scheduleInject();
        };
        if (document.documentElement) start();
        else document.addEventListener('DOMContentLoaded', start, { once: true });
    }

    // ---------------------------------------------------------------------
    // UI
    // ---------------------------------------------------------------------

    function ensureStyles() {
        if (document.getElementById(`${SCRIPT.id}-style`)) return;
        const style = document.createElement('style');
        style.id = `${SCRIPT.id}-style`;
        style.textContent = `
            .${SCRIPT.id}-view {
                margin-left: 8px; padding: 0 7px; height: 24px; min-width: 38px;
                border: 1px solid var(--colorControlBorder,#8a8886); border-radius: 2px;
                background: transparent; color: var(--colorLink,#0078d4);
                font: 12px "Segoe UI",sans-serif; cursor: pointer;
            }
            .${SCRIPT.id}-view:hover { background: var(--colorControlBackgroundHover,#f3f2f1); }
            #${SCRIPT.id}-overlay {
                position: fixed; inset: 0; z-index: 360000; display: flex; align-items: center; justify-content: center;
                padding: 20px; box-sizing: border-box; background: rgba(0,0,0,.42); font-family: "Segoe UI",sans-serif;
            }
            #${SCRIPT.id}-dialog {
                width: min(1560px, calc(100vw - 40px)); height: min(900px, calc(100vh - 40px));
                display: flex; flex-direction: column; overflow: hidden;
                background: var(--colorContainerBackgroundPrimary,#fff); color: var(--colorTextPrimary,#323130);
                border: 1px solid var(--colorContainerBorderSecondary,#d2d0ce);
                box-shadow: var(--shadowLevel4,0 25.6px 57.6px rgba(0,0,0,.32));
            }
            .tm-di-titlebar { display:flex; align-items:center; gap:12px; min-height:58px; padding:0 18px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-titlewrap { min-width:0; flex:1; }
            .tm-di-title { margin:0; font-size:20px; line-height:26px; font-weight:600; }
            .tm-di-subtitle { margin-top:2px; color:var(--colorTextSecondary,#605e5c); font-size:12px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
            .tm-di-button { height:32px; padding:0 10px; border:1px solid var(--colorControlBorder,#8a8886); border-radius:2px; background:transparent; color:var(--colorTextPrimary,#323130); font:13px "Segoe UI",sans-serif; cursor:pointer; }
            .tm-di-button:hover:not(:disabled) { background:var(--colorControlBackgroundHover,#f3f2f1); }
            .tm-di-button:disabled { color:var(--colorTextDisabled,#a19f9d); cursor:default; }
            .tm-di-close { width:34px; padding:0; font-size:18px; border:0; }
            .tm-di-progress { height:3px; flex:0 0 3px; background:var(--colorContainerBackgroundSecondary,#f3f2f1); overflow:hidden; }
            .tm-di-progress > div { height:100%; width:0; background:var(--colorControlBackgroundBrand,#0078d4); transition:width .2s ease; }
            .tm-di-status { min-height:26px; padding:6px 18px; box-sizing:border-box; color:var(--colorTextSecondary,#605e5c); font-size:12px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-summary { display:grid; grid-template-columns:repeat(6,minmax(110px,1fr)); gap:10px; padding:12px 18px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-card { min-width:0; padding:10px 12px; background:var(--colorContainerBackgroundSecondary,#f3f2f1); border:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-card-value { font-size:23px; line-height:28px; font-weight:600; }
            .tm-di-card-label { margin-top:2px; color:var(--colorTextSecondary,#605e5c); font-size:11px; }
            .tm-di-main { display:grid; grid-template-columns:minmax(300px,380px) minmax(0,1fr); flex:1; min-height:0; overflow:hidden; }
            .tm-di-modelpane { min-width:0; min-height:0; overflow:auto; border-right:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-section-title { position:sticky; top:0; z-index:2; margin:0; padding:12px 14px 8px; background:var(--colorContainerBackgroundPrimary,#fff); font-size:14px; font-weight:600; }
            .tm-di-model-table, .tm-di-device-table { width:100%; border-collapse:collapse; font-size:12px; }
            .tm-di-model-table th, .tm-di-device-table th { position:sticky; top:0; z-index:2; text-align:left; background:var(--colorContainerBackgroundPrimary,#fff); color:var(--colorTextSecondary,#605e5c); border-bottom:1px solid var(--colorContainerBorderSecondary,#d2d0ce); padding:8px 9px; font-weight:600; white-space:nowrap; cursor:pointer; }
            .tm-di-model-table td, .tm-di-device-table td { border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); padding:7px 9px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
            .tm-di-model-table tbody tr { cursor:pointer; }
            .tm-di-model-table tbody tr:hover, .tm-di-device-table tbody tr:hover { background:var(--todoFocusRowHover,var(--colorControlBackgroundHover,#f3f2f1)); }
            .tm-di-right { display:flex; flex-direction:column; min-width:0; min-height:0; }
            .tm-di-toolbar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; padding:10px 12px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-di-search { flex:1 1 260px; min-width:180px; height:32px; padding:0 9px; box-sizing:border-box; border:1px solid var(--colorControlBorder,#8a8886); background:var(--colorControlBackground,#fff); color:var(--colorTextPrimary,#323130); outline:none; }
            .tm-di-select { height:32px; max-width:220px; min-width:135px; padding:0 7px; border:1px solid var(--colorControlBorder,#8a8886); background:var(--colorControlBackground,#fff); color:var(--colorTextPrimary,#323130); }
            .tm-di-tablewrap { flex:1; min-height:0; overflow:auto; }
            .tm-di-device-table { table-layout:fixed; min-width:1660px; }
            .tm-di-col-device { width:145px; } .tm-di-col-manufacturer { width:125px; } .tm-di-col-model { width:190px; }
            .tm-di-col-serial { width:125px; } .tm-di-col-os { width:145px; } .tm-di-col-user { width:210px; }
            .tm-di-col-state { width:110px; } .tm-di-col-policy { width:250px; } .tm-di-col-sync { width:145px; } .tm-di-col-id { width:255px; }
            .tm-di-footer { display:flex; align-items:center; gap:10px; min-height:42px; padding:0 12px; border-top:1px solid var(--colorContainerBorderPrimary,#edebe9); color:var(--colorTextSecondary,#605e5c); font-size:12px; }
            .tm-di-spacer { flex:1; }
            .tm-di-error { color:var(--colorTextError,#d13438); }
            .tm-di-note { padding:8px 12px; background:var(--colorContainerBackgroundInfo,#deecf9); color:var(--colorTextPrimary,#323130); border-bottom:1px solid var(--colorControlBorderInfo,#0078d4); font-size:12px; }
            .tm-di-badge { display:inline-block; padding:2px 7px; border-radius:10px; background:var(--colorContainerBackgroundSecondary,#f3f2f1); }
            @media (max-width:1000px) {
                #${SCRIPT.id}-overlay { padding:8px; }
                #${SCRIPT.id}-dialog { width:calc(100vw - 16px); height:calc(100vh - 16px); }
                .tm-di-main { grid-template-columns:1fr; grid-template-rows:240px minmax(0,1fr); }
                .tm-di-modelpane { border-right:0; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
                .tm-di-summary { grid-template-columns:repeat(3,1fr); }
            }
        `;
        (document.head || document.documentElement).appendChild(style);
    }

    function removeOverlay() {
        state.currentLoadAbort?.abort();
        state.currentLoadAbort = null;
        document.getElementById(`${SCRIPT.id}-overlay`)?.remove();
    }

    function showDiagnosticDialog(title, message) {
        ensureStyles();
        removeOverlay();
        const overlay = document.createElement('div');
        overlay.id = `${SCRIPT.id}-overlay`;
        overlay.innerHTML = `
            <div id="${SCRIPT.id}-dialog" style="width:min(760px,calc(100vw - 40px));height:auto;max-height:80vh;">
                <div class="tm-di-titlebar">
                    <div class="tm-di-titlewrap"><h2 class="tm-di-title">${escapeHtml(title)}</h2></div>
                    <button class="tm-di-button tm-di-close" data-action="close">×</button>
                </div>
                <div style="padding:18px;line-height:1.5;font-size:13px;overflow:auto;">
                    <div>${escapeHtml(message)}</div>
                    <details style="margin-top:14px;"><summary>Observed Graph tokens</summary><pre style="white-space:pre-wrap;font-size:11px;">${escapeHtml(JSON.stringify(describeGraphTokens(), null, 2))}</pre></details>
                </div>
            </div>`;
        overlay.addEventListener('click', e => { if (e.target === overlay || e.target.closest('[data-action="close"]')) removeOverlay(); });
        document.body.appendChild(overlay);
    }

    function createOverlay(driver) {
        ensureStyles();
        removeOverlay();

        const overlay = document.createElement('div');
        overlay.id = `${SCRIPT.id}-overlay`;
        overlay.innerHTML = `
            <div id="${SCRIPT.id}-dialog">
                <div class="tm-di-titlebar">
                    <div class="tm-di-titlewrap">
                        <h2 class="tm-di-title">Driver impact</h2>
                        <div class="tm-di-subtitle">${escapeHtml(driver.name)} · ${escapeHtml(driver.manufacturer)} · Catalog ${escapeHtml(String(driver.driverId || '').split('_')[0])}</div>
                    </div>
                    <button class="tm-di-button" data-action="refresh">Refresh</button>
                    <button class="tm-di-button tm-di-close" data-action="close" title="Close">×</button>
                </div>
                <div class="tm-di-progress"><div></div></div>
                <div class="tm-di-status">Preparing...</div>
                <div class="tm-di-summary">
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="portal">${escapeHtml(driver.applicableDeviceCount ?? '–')}</div><div class="tm-di-card-label">Portal applicable count</div></div>
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="reported">–</div><div class="tm-di-card-label">Reported devices</div></div>
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="installed">–</div><div class="tm-di-card-label">Installed</div></div>
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="inprogress">–</div><div class="tm-di-card-label">Open / in progress</div></div>
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="attention">–</div><div class="tm-di-card-label">Needs attention</div></div>
                    <div class="tm-di-card"><div class="tm-di-card-value" data-summary="models">–</div><div class="tm-di-card-label">Models</div></div>
                </div>
                <div class="tm-di-note" data-note>
                    Device status comes from the Intune Windows Driver Update report. The portal's “Applicable devices” count is current applicability; report rows include deployment status and retained history, so the counts can legitimately differ.
                </div>
                <div class="tm-di-main">
                    <div class="tm-di-modelpane">
                        <h3 class="tm-di-section-title">Model distribution</h3>
                        <table class="tm-di-model-table">
                            <thead><tr><th>Manufacturer</th><th>Model</th><th>Devices</th><th>Installed</th><th>In progress</th><th>Problems</th><th>%</th></tr></thead>
                            <tbody data-model-body><tr><td colspan="7">Loading...</td></tr></tbody>
                        </table>
                    </div>
                    <div class="tm-di-right">
                        <div class="tm-di-toolbar">
                            <input class="tm-di-search" type="search" placeholder="Search devices, model, serial, user, ID..." data-filter="search">
                            <select class="tm-di-select" data-filter="manufacturer"><option value="">All manufacturers</option></select>
                            <select class="tm-di-select" data-filter="model"><option value="">All models</option></select>
                            <select class="tm-di-select" data-filter="state"><option value="">All states</option></select>
                            <button class="tm-di-button" data-action="copy">Copy device names</button>
                            <button class="tm-di-button" data-action="csv">Export CSV</button>
                            <button class="tm-di-button" data-action="reset">Reset filters</button>
                        </div>
                        <div class="tm-di-tablewrap">
                            <table class="tm-di-device-table">
                                <thead><tr>
                                    <th class="tm-di-col-device" data-sort="deviceName">Device</th>
                                    <th class="tm-di-col-manufacturer" data-sort="manufacturer">Manufacturer</th>
                                    <th class="tm-di-col-model" data-sort="model">Model</th>
                                    <th class="tm-di-col-serial" data-sort="serialNumber">Serial</th>
                                    <th class="tm-di-col-os" data-sort="osVersion">OS</th>
                                    <th class="tm-di-col-user" data-sort="userPrincipalName">User</th>
                                    <th class="tm-di-col-state" data-sort="updateState">State</th>
                                    <th class="tm-di-col-policy" data-sort="policyName">Policy</th>
                                    <th class="tm-di-col-sync" data-sort="lastScanTime">Last WU scan</th>
                                    <th class="tm-di-col-id" data-sort="entraDeviceId">Entra device ID</th>
                                </tr></thead>
                                <tbody data-device-body><tr><td colspan="10">Loading...</td></tr></tbody>
                            </table>
                        </div>
                        <div class="tm-di-footer"><span data-footer-count>0 devices</span><span class="tm-di-spacer"></span><span>v${SCRIPT.version}</span></div>
                    </div>
                </div>
            </div>`;
        document.body.appendChild(overlay);
        return overlay;
    }

    function formatDate(value) {
        if (!value) return '';
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
    }

    function buildOverlayController(overlay, driver) {
        const refs = {
            status: overlay.querySelector('.tm-di-status'),
            progress: overlay.querySelector('.tm-di-progress > div'),
            modelBody: overlay.querySelector('[data-model-body]'),
            deviceBody: overlay.querySelector('[data-device-body]'),
            footerCount: overlay.querySelector('[data-footer-count]'),
            manufacturer: overlay.querySelector('[data-filter="manufacturer"]'),
            model: overlay.querySelector('[data-filter="model"]'),
            state: overlay.querySelector('[data-filter="state"]'),
            search: overlay.querySelector('[data-filter="search"]'),
        };

        const vm = {
            allRows: [],
            filteredRows: [],
            models: [],
            sortKey: 'manufacturer',
            sortDesc: false,
        };

        const setProgress = (text, percent = null, error = false) => {
            refs.status.textContent = text;
            refs.status.classList.toggle('tm-di-error', Boolean(error));
            if (percent !== null) refs.progress.style.width = `${Math.max(0, Math.min(100, percent))}%`;
        };

        function updateFilterOptions() {
            const manufacturers = [...new Set(vm.allRows.map(x => x.manufacturer).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
            const selectedManufacturer = refs.manufacturer.value;
            refs.manufacturer.innerHTML = '<option value="">All manufacturers</option>' + manufacturers.map(x => `<option>${escapeHtml(x)}</option>`).join('');
            refs.manufacturer.value = manufacturers.includes(selectedManufacturer) ? selectedManufacturer : '';

            const models = [...new Set(vm.allRows
                .filter(x => !refs.manufacturer.value || x.manufacturer === refs.manufacturer.value)
                .map(x => x.model).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
            const selectedModel = refs.model.value;
            refs.model.innerHTML = '<option value="">All models</option>' + models.map(x => `<option>${escapeHtml(x)}</option>`).join('');
            refs.model.value = models.includes(selectedModel) ? selectedModel : '';

            const states = [...new Set(vm.allRows.map(x => x.updateState).filter(Boolean))].sort((a,b)=>a.localeCompare(b));
            const selectedState = refs.state.value;
            refs.state.innerHTML = '<option value="">All states</option>' + states.map(x => `<option>${escapeHtml(x)}</option>`).join('');
            refs.state.value = states.includes(selectedState) ? selectedState : '';
        }

        function applyFilters() {
            const q = refs.search.value.trim().toLowerCase();
            const manufacturer = refs.manufacturer.value;
            const model = refs.model.value;
            const stateFilter = refs.state.value;

            vm.filteredRows = vm.allRows.filter(row => {
                if (manufacturer && row.manufacturer !== manufacturer) return false;
                if (model && row.model !== model) return false;
                if (stateFilter && row.updateState !== stateFilter) return false;
                if (q) {
                    const hay = [row.deviceName,row.manufacturer,row.model,row.serialNumber,row.operatingSystem,row.osVersion,row.userPrincipalName,row.updateState,row.entraDeviceId,row.intuneDeviceId]
                        .join('\n').toLowerCase();
                    if (!hay.includes(q)) return false;
                }
                return true;
            });
            renderDevices();
        }

        function renderModels() {
            refs.modelBody.innerHTML = vm.models.length ? vm.models.map(x => `
                <tr data-manufacturer="${escapeHtml(x.manufacturer)}" data-model="${escapeHtml(x.model)}">
                    <td title="${escapeHtml(x.manufacturer)}">${escapeHtml(x.manufacturer)}</td>
                    <td title="${escapeHtml(x.model)}">${escapeHtml(x.model)}</td>
                    <td>${x.count}</td>
                    <td>${x.installed}</td>
                    <td>${x.inProgress}</td>
                    <td>${x.problems}</td>
                    <td>${x.percentage.toFixed(1)}%</td>
                </tr>`).join('') : '<tr><td colspan="7">No model metadata available.</td></tr>';
        }

        function renderDevices() {
            const rows = [...vm.filteredRows].sort((a,b) => {
                const av = String(a[vm.sortKey] ?? '');
                const bv = String(b[vm.sortKey] ?? '');
                const cmp = av.localeCompare(bv, undefined, { numeric: true, sensitivity: 'base' });
                return vm.sortDesc ? -cmp : cmp;
            });

            refs.deviceBody.innerHTML = rows.length ? rows.map(row => `
                <tr>
                    <td title="${escapeHtml(row.deviceName)}">${escapeHtml(row.deviceName || '(unresolved)')}</td>
                    <td title="${escapeHtml(row.manufacturer)}">${escapeHtml(row.manufacturer)}</td>
                    <td title="${escapeHtml(row.model)}">${escapeHtml(row.model)}</td>
                    <td title="${escapeHtml(row.serialNumber)}">${escapeHtml(row.serialNumber)}</td>
                    <td title="${escapeHtml(`${row.operatingSystem} ${row.osVersion}`)}">${escapeHtml([row.operatingSystem,row.osVersion].filter(Boolean).join(' '))}</td>
                    <td title="${escapeHtml(row.userPrincipalName)}">${escapeHtml(row.userPrincipalName)}</td>
                    <td title="${escapeHtml([row.aggregateState,row.updateSubstate,row.alertSubType].filter(Boolean).join(' · '))}"><span class="tm-di-badge">${escapeHtml(row.updateState)}</span></td>
                    <td title="${escapeHtml(row.policyName)}">${escapeHtml(row.policyName)}</td>
                    <td title="${escapeHtml(formatDate(row.lastScanTime))}">${escapeHtml(formatDate(row.lastScanTime))}</td>
                    <td title="${escapeHtml(row.entraDeviceId)}">${escapeHtml(row.entraDeviceId)}</td>
                </tr>`).join('') : '<tr><td colspan="10">No devices match the current filters.</td></tr>';
            refs.footerCount.textContent = `${rows.length} of ${vm.allRows.length} devices`;
        }

        function renderSummary() {
            const uniqueModels = new Set(vm.allRows.filter(x => x.model).map(x => `${x.manufacturer}|${x.model}`));
            const installed = vm.allRows.filter(x => String(x.updateState).toLowerCase() === 'installed').length;
            const attention = vm.allRows.filter(x => {
                const text = `${x.aggregateState || ''} ${x.updateState || ''}`.toLowerCase();
                return text.includes('needs attention') || text.includes('error') || text.includes('failed');
            }).length;
            const inProgress = vm.allRows.length - installed - attention;
            overlay.querySelector('[data-summary="reported"]').textContent = String(vm.allRows.length);
            overlay.querySelector('[data-summary="installed"]').textContent = String(installed);
            overlay.querySelector('[data-summary="inprogress"]').textContent = String(Math.max(0, inProgress));
            overlay.querySelector('[data-summary="attention"]').textContent = String(attention);
            overlay.querySelector('[data-summary="models"]').textContent = String(uniqueModels.size);
        }

        async function load() {
            state.currentLoadAbort?.abort();
            const controller = new AbortController();
            state.currentLoadAbort = controller;
            refs.deviceBody.innerHTML = '<tr><td colspan="10">Loading...</td></tr>';
            refs.modelBody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';
            setProgress('Checking available Microsoft Graph permissions...', 3);

            const intuneToken = await waitForIntuneGraphToken(['DeviceManagementManagedDevices.Read.All'], 12000);
            if (!intuneToken) {
                const observed = describeGraphTokens();
                const details = observed.length
                    ? observed.map(x => `${x.source}: ${x.scopes.join(', ') || '(no delegated scopes)'}`).join(' | ')
                    : 'No Microsoft Graph JWT was found in fetch/XHR, MSAL sessionStorage, authBootstrapState, portal messages, or sibling frames.';
                setProgress('No Intune-capable Graph token is available after token synchronization and Intune Devices warm-up.', 100, true);
                refs.deviceBody.innerHTML = `<tr><td colspan="10">The Driver Update report requires DeviceManagementManagedDevices.Read.All/ReadWrite.All.<br><small>${escapeHtml(details)}</small></td></tr>`;
                refs.modelBody.innerHTML = '<tr><td colspan="7">No data.</td></tr>';
                return;
            }

            try {
                let activeDriver = await ensureDriverMetadata(driver, controller.signal, text => setProgress(text, 8));
                Object.assign(driver, activeDriver);
                overlay.querySelector('.tm-di-subtitle').textContent = `${driver.name} · ${driver.manufacturer} · Catalog ${driver.driverId}`;

                setProgress('Preparing Intune Driver Update report...', 12);
                const reportRows = await loadDriverReportRows(driver, controller.signal, text => setProgress(text, 28));
                setProgress(`Driver report returned ${reportRows.length} unique devices. Resolving hardware metadata...`, 55);

                const aadIds = reportRows.map(x => x.entraDeviceId).filter(Boolean);
                const metadataWarnings = [];
                let managedMap = new Map();
                try {
                    managedMap = await resolveManagedDevicesFromReport(reportRows, controller.signal, text => setProgress(text, 72));
                } catch (e) {
                    if (e?.name === 'AbortError') throw e;
                    warn('Hardware metadata enrichment failed; continuing with report data.', e);
                    metadataWarnings.push(`Intune hardware metadata incomplete: ${e.message || e}`);
                }

                const missing = aadIds.filter(id => !managedMap.has(id.toLowerCase()));
                let entraMap = new Map();
                if (missing.length) {
                    try {
                        entraMap = await resolveEntraDevicesFallback(missing, controller.signal, text => setProgress(text, 86));
                    } catch (e) {
                        if (e?.name === 'AbortError') throw e;
                        warn('Entra fallback metadata failed; continuing with report data.', e);
                        metadataWarnings.push(`Entra fallback metadata incomplete: ${e.message || e}`);
                    }
                }

                vm.allRows = toDeviceRows(reportRows, managedMap, entraMap);
                vm.models = aggregateModels(vm.allRows);
                vm.filteredRows = [...vm.allRows];
                updateFilterOptions();
                renderSummary();
                renderModels();
                applyFilters();

                const expected = Number(driver.applicableDeviceCount);
                const mismatch = Number.isFinite(expected) && expected !== vm.allRows.length;
                const baseMessage = mismatch
                    ? `Loaded ${vm.allRows.length} reported devices. Intune currently shows ${expected} applicable devices; report history and current applicability are different data sets.`
                    : `Loaded ${vm.allRows.length} reported devices for this driver.`;
                const unresolvedHardware = vm.allRows.filter(x => !x.manufacturer && !x.model).length;
                const warningText = metadataWarnings.length
                    ? ` Hardware metadata warning: ${metadataWarnings.join(' | ')}`
                    : (unresolvedHardware ? ` Hardware metadata unavailable for ${unresolvedHardware} device(s).` : '');
                setProgress(`${baseMessage}${warningText}`, 100, false);
            } catch (e) {
                if (e?.name === 'AbortError') return;
                warn(e);
                setProgress(e.message || String(e), 100, true);
                refs.deviceBody.innerHTML = `<tr><td colspan="10">${escapeHtml(e.message || String(e))}</td></tr>`;
                refs.modelBody.innerHTML = '<tr><td colspan="7">No data.</td></tr>';
            }
        }

        overlay.addEventListener('click', async e => {
            if (e.target === overlay || e.target.closest('[data-action="close"]')) {
                removeOverlay(); return;
            }
            const action = e.target.closest('[data-action]')?.dataset.action;
            if (action === 'refresh') load();
            if (action === 'reset') {
                refs.search.value = ''; refs.manufacturer.value = ''; refs.model.value = ''; refs.state.value = '';
                updateFilterOptions(); applyFilters();
            }
            if (action === 'copy') {
                const names = vm.filteredRows.map(x => x.deviceName).filter(Boolean).join('\r\n');
                try { await navigator.clipboard.writeText(names); setProgress(`Copied ${vm.filteredRows.filter(x=>x.deviceName).length} device names.`, 100); }
                catch { setProgress('Clipboard access was blocked by the browser.', 100, true); }
            }
            if (action === 'csv') {
                const cols = [
                    ['DeviceName','deviceName'], ['Manufacturer','manufacturer'], ['Model','model'], ['SerialNumber','serialNumber'],
                    ['OperatingSystem','operatingSystem'], ['OSVersion','osVersion'], ['UPN','userPrincipalName'], ['ComplianceState','complianceState'],
                    ['UpdateState','updateState'], ['UpdateSubstate','updateSubstate'], ['UpdateSubstateTime','updateSubstateTime'], ['AggregateState','aggregateState'], ['AlertSubType','alertSubType'],
                    ['LastWUScanTime','lastScanTime'], ['LastIntuneSync','lastSyncDateTime'], ['Policy','policyName'], ['PolicyCount','policyCount'], ['EntraDeviceId','entraDeviceId'], ['IntuneDeviceId','intuneDeviceId'],
                ];
                const csv = '\uFEFF' + [
                    cols.map(c => csvEscape(c[0])).join(';'),
                    ...vm.filteredRows.map(row => cols.map(c => csvEscape(row[c[1]])).join(';'))
                ].join('\r\n');
                const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `Intune-Driver-Impact-${String(driver.driverVersion || 'driver').replace(/[^A-Za-z0-9_.-]/g,'_')}.csv`;
                document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
            }
        });

        refs.search.addEventListener('input', applyFilters);
        refs.manufacturer.addEventListener('change', () => { updateFilterOptions(); applyFilters(); });
        refs.model.addEventListener('change', applyFilters);
        refs.state.addEventListener('change', applyFilters);

        refs.modelBody.addEventListener('click', e => {
            const tr = e.target.closest('tr[data-model]');
            if (!tr) return;
            refs.manufacturer.value = tr.dataset.manufacturer;
            updateFilterOptions();
            refs.model.value = tr.dataset.model;
            applyFilters();
        });

        overlay.querySelectorAll('.tm-di-device-table th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (vm.sortKey === key) vm.sortDesc = !vm.sortDesc;
                else { vm.sortKey = key; vm.sortDesc = false; }
                renderDevices();
            });
        });

        return { load };
    }

    function openImpactOverlay(driver) {
        const overlay = createOverlay(driver);
        const controller = buildOverlayController(overlay, driver);
        controller.load();
    }

    // ---------------------------------------------------------------------
    // Start
    // ---------------------------------------------------------------------

    // Auth hooks are installed first at document-start so we do not miss portal
    // token traffic before the ReactView UI is mounted.
    patchFetch();
    patchXhr();
    installTokenBridge();
    scanStorageForJwt();
    requestIntuneTokenSync({ warmup: false });
    startUiObserver();

    // Storage tokens can appear after MSAL initializes.
    setTimeout(scanStorageForJwt, 1500);
    setTimeout(scanStorageForJwt, 5000);
    setInterval(() => {
        if (!document.hidden) {
            scanStorageForJwt();
            scheduleInject();
        }
    }, 15000);

    log(`Loaded v${SCRIPT.version}`, location.href);
})();
