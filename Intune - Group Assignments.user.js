// ==UserScript==
// @name         Intune - Group Assignments
// @namespace    xento.betterintuneui
// @version      1.4.0
// @description  Shows all direct Intune assignments (Include/Exclude) for the currently opened Entra group.
// @author       Xento
// @match        https://intune.microsoft.com/*
// @match        https://*.reactblade.portal.azure.net/*
// @match        https://*.reactblade-ms.portal.azure.net/*
// @match        https://*.reactblade-rc.portal.azure.net/*
// @run-at       document-start
// @grant        unsafeWindow
// @grant        GM_xmlhttpRequest
// @connect      graph.microsoft.com
// ==/UserScript==

(() => {
    'use strict';

    const SCRIPT_ID = 'tm-intune-group-assignments-v1';
    const DEBUG = false;
    const GRAPH_ROOT = 'https://graph.microsoft.com';
    const GUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;

    const log = (...args) => DEBUG && console.debug(`[${SCRIPT_ID}]`, ...args);
    const info = (...args) => console.info(`[${SCRIPT_ID}]`, ...args);
    const warn = (...args) => console.warn(`[${SCRIPT_ID}]`, ...args);
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    /*
     * Workloads are intentionally data-driven. Microsoft Graph does not expose one
     * reverse-lookup endpoint for "everything assigned to group X". We therefore
     * enumerate the Intune workloads and filter their assignments by groupId.
     *
     * strategy:
     *   expand = first try ?$expand=assignments, then fall back to collection + batch
     *   batch  = collection + /{id}/assignments through Microsoft Graph $batch
     *   appProtection = managedAppPolicies needs a type-specific assignment URL
     */
    const WORKLOADS = [
        { type: 'Applications', path: '/beta/deviceAppManagement/mobileApps', strategy: 'batch' },
        { type: 'Configuration profiles', path: '/beta/deviceManagement/deviceConfigurations', strategy: 'expand' },
        { type: 'Settings Catalog / Endpoint Security', path: '/beta/deviceManagement/configurationPolicies', strategy: 'expand' },
        { type: 'Compliance policies', path: '/beta/deviceManagement/deviceCompliancePolicies', strategy: 'expand' },
        { type: 'Compliance policies (Settings Catalog)', path: '/beta/deviceManagement/compliancePolicies', strategy: 'expand' },
        { type: 'Security baselines', path: '/beta/deviceManagement/intents', strategy: 'expand' },
        { type: 'Administrative Templates', path: '/beta/deviceManagement/groupPolicyConfigurations', strategy: 'expand' },
        { type: 'Remediations', path: '/beta/deviceManagement/deviceHealthScripts', strategy: 'expand' },
        { type: 'PowerShell scripts', path: '/beta/deviceManagement/deviceManagementScripts', strategy: 'expand' },
        { type: 'macOS shell scripts', path: '/beta/deviceManagement/deviceShellScripts', strategy: 'expand' },
        { type: 'macOS custom attribute scripts', path: '/beta/deviceManagement/deviceCustomAttributeShellScripts', strategy: 'expand' },
        { type: 'Feature update profiles', path: '/beta/deviceManagement/windowsFeatureUpdateProfiles', strategy: 'expand' },
        { type: 'Quality update profiles', path: '/beta/deviceManagement/windowsQualityUpdateProfiles', strategy: 'expand' },
        { type: 'Windows update policies', path: '/beta/deviceManagement/windowsQualityUpdatePolicies', strategy: 'expand' },
        { type: 'Driver update profiles', path: '/beta/deviceManagement/windowsDriverUpdateProfiles', strategy: 'expand' },
        { type: 'Autopilot deployment profiles', path: '/beta/deviceManagement/windowsAutopilotDeploymentProfiles', strategy: 'expand' },
        { type: 'Enrollment configurations / ESP', path: '/beta/deviceManagement/deviceEnrollmentConfigurations', strategy: 'expand' },
        { type: 'Terms and Conditions', path: '/beta/deviceManagement/termsAndConditions', strategy: 'batch' },
        { type: 'Intune branding profiles', path: '/beta/deviceManagement/intuneBrandingProfiles', strategy: 'expand' },
        { type: 'WDAC supplemental policies', path: '/beta/deviceAppManagement/wdacSupplementalPolicies', strategy: 'expand' },
        { type: 'Windows Information Protection', path: '/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies', strategy: 'expand' },
        { type: 'App configuration (managed devices)', path: '/beta/deviceAppManagement/mobileAppConfigurations', strategy: 'batch' },
        { type: 'iOS LoB provisioning configurations', path: '/beta/deviceAppManagement/iosLobAppProvisioningConfigurations', strategy: 'batch' },
        { type: 'App protection / managed app policies', path: '/beta/deviceAppManagement/managedAppPolicies', strategy: 'appProtection' },
        { type: 'Cloud PC provisioning policies', path: '/beta/deviceManagement/virtualEndpoint/provisioningPolicies', strategy: 'expand', optional: true }
    ];

    // -------------------------------------------------------------------------
    // Authentication / token discovery
    // -------------------------------------------------------------------------

    /*
     * This follows the same model as the user's other working Intune/Entra
     * Tampermonkey scripts:
     *   1. Capture Bearer tokens from the portal's fetch/XHR traffic.
     *   2. Read MSAL AccessToken entries already present in sessionStorage.
     *   3. Read the Azure portal bootstrap token cache when available.
     *   4. Keep several Microsoft Graph tokens in memory and try the best
     *      matching token first. On 401/403, try the next candidate.
     *   5. Share captured tokens between the Intune shell and ReactBlade frames
     *      through window.postMessage. No token is persisted by Tampermonkey.
     */

    const TOKEN_BRIDGE_MARKER = `${SCRIPT_ID}:token-bridge-v14`;
    const TOKEN_POOL = new Map();
    const BRIDGE_CLIENTS = [];
    const GRAPH_AUDIENCES = new Set([
        '00000003-0000-0000-c000-000000000000',
        'https://graph.microsoft.com',
        'https://graph.microsoft.com/'
    ]);

    function normalizeUrl(input) {
        try {
            if (typeof input === 'string') return input;
            if (input && typeof input.url === 'string') return input.url;
            return String(input || '');
        } catch {
            return '';
        }
    }

    function authFromHeaders(headers, pageWindow) {
        if (!headers) return '';
        try {
            if (typeof headers.get === 'function') {
                const value = headers.get('Authorization') || headers.get('authorization');
                if (value) return String(value);
            }
        } catch { /* cross-realm object */ }

        try {
            if (pageWindow?.Headers && headers instanceof pageWindow.Headers) {
                const value = headers.get('Authorization') || headers.get('authorization');
                if (value) return String(value);
            }
        } catch { /* cross-realm object */ }

        try {
            if (typeof headers === 'string') {
                const match = headers.match(/(?:^|\r?\n)authorization\s*:\s*([^\r\n]+)/i);
                return match ? String(match[1] || '').trim() : '';
            }
            if (Array.isArray(headers)) {
                const hit = headers.find(h => Array.isArray(h) && String(h[0]).toLowerCase() === 'authorization');
                return hit ? String(hit[1] || '') : '';
            }
            if (typeof headers === 'object') {
                for (const [key, value] of Object.entries(headers)) {
                    if (String(key).toLowerCase() === 'authorization') return String(value || '');
                }
            }
        } catch { /* ignore */ }
        return '';
    }

    function decodeJwtPayload(token) {
        try {
            const part = String(token || '').split('.')[1];
            if (!part) return null;
            const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
            const binary = atob(padded);
            const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
            return JSON.parse(new TextDecoder().decode(bytes));
        } catch {
            return null;
        }
    }

    function normalizeToken(value) {
        let token = String(value || '').trim();
        if (/^Bearer\s+/i.test(token)) token = token.replace(/^Bearer\s+/i, '').trim();
        return token;
    }

    function getTokenScopes(claims) {
        const values = [];
        if (typeof claims?.scp === 'string') values.push(...claims.scp.split(/\s+/));
        if (Array.isArray(claims?.roles)) values.push(...claims.roles);
        return [...new Set(values.filter(Boolean))];
    }

    function hasScope(scopes, readName, writeName) {
        return scopes.some(scope => scope === readName || scope === writeName);
    }

    function inspectToken(rawToken) {
        const token = normalizeToken(rawToken);
        const claims = decodeJwtPayload(token);
        const scopes = getTokenScopes(claims);
        const aud = String(claims?.aud || '').toLowerCase();
        const now = Math.floor(Date.now() / 1000);
        const expired = Number(claims?.exp || 0) > 0 && Number(claims.exp) <= now + 30;
        const graphAudience = GRAPH_AUDIENCES.has(aud);

        const apps = hasScope(scopes, 'DeviceManagementApps.Read.All', 'DeviceManagementApps.ReadWrite.All');
        const configuration = hasScope(scopes, 'DeviceManagementConfiguration.Read.All', 'DeviceManagementConfiguration.ReadWrite.All');
        const scripts = hasScope(scopes, 'DeviceManagementScripts.Read.All', 'DeviceManagementScripts.ReadWrite.All');
        const service = scopes.some(scope => /^DeviceManagementServiceConfig(?:uration)?\.Read(?:Write)?\.All$/i.test(scope));
        const managedDevices = hasScope(scopes, 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.ReadWrite.All');
        const cloudPc = scopes.some(scope => /^CloudPC\.Read(?:Write)?\.All$/i.test(scope));
        const intuneScopeCount = scopes.filter(scope => /^DeviceManagement/i.test(scope)).length;

        let score = intuneScopeCount;
        if (apps) score += 1000;
        if (configuration) score += 900;
        if (scripts) score += 700;
        if (service) score += 500;
        if (managedDevices) score += 300;
        if (cloudPc) score += 200;

        return {
            token,
            claims,
            scopes,
            aud,
            expired,
            graphAudience,
            apps,
            configuration,
            scripts,
            service,
            managedDevices,
            cloudPc,
            intuneScopeCount,
            intuneLike: Boolean(intuneScopeCount || cloudPc),
            score
        };
    }

    function tokenFingerprint(token) {
        const info = inspectToken(token);
        const appId = info.claims?.azp || info.claims?.appid || '?';
        const oid = info.claims?.oid || '?';
        const exp = info.claims?.exp || '?';
        return `${appId}:${oid}:${exp}:${String(token).slice(-12)}`;
    }

    function isAllowedBridgeOrigin(origin) {
        return origin === 'https://intune.microsoft.com' ||
            /^https:\/\/[^/]+\.reactblade(?:-ms|-rc)?\.portal\.azure\.net$/i.test(origin);
    }

    function addBridgeClient(win, origin) {
        if (!win || !isAllowedBridgeOrigin(origin)) return;
        if (!BRIDGE_CLIENTS.some(c => c.win === win)) BRIDGE_CLIENTS.push({ win, origin });
    }

    function sendTokenToTop(token, source) {
        if (window.top === window) return;
        try {
            window.top.postMessage({
                marker: TOKEN_BRIDGE_MARKER,
                type: 'token',
                token,
                source: source || location.href
            }, 'https://intune.microsoft.com');
        } catch { /* ignore */ }
    }

    function broadcastTokenFromTop(token, source) {
        if (window.top !== window) return;
        for (let i = BRIDGE_CLIENTS.length - 1; i >= 0; i--) {
            const client = BRIDGE_CLIENTS[i];
            try {
                client.win.postMessage({
                    marker: TOKEN_BRIDGE_MARKER,
                    type: 'token',
                    token,
                    source: source || 'Intune shell'
                }, client.origin);
            } catch {
                BRIDGE_CLIENTS.splice(i, 1);
            }
        }
    }

    function addGraphToken(rawToken, source = '', publish = true) {
        const info = inspectToken(rawToken);
        if (!info.token || info.token.length < 100 || !info.claims || info.expired || !info.graphAudience) return false;

        const fingerprint = tokenFingerprint(info.token);
        const existing = TOKEN_POOL.get(fingerprint);
        if (existing) {
            existing.lastSeen = Date.now();
            if (source) existing.sources.add(source);
            return true;
        }

        const entry = {
            token: info.token,
            info,
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            sources: new Set(source ? [source] : [])
        };
        TOKEN_POOL.set(fingerprint, entry);

        if (info.intuneLike) {
            console.info(`[${SCRIPT_ID}] Intune-capable Microsoft Graph token discovered.`, {
                appId: info.claims?.azp || info.claims?.appid || '',
                scopes: info.scopes,
                source
            });
        } else {
            log('Additional Microsoft Graph token discovered.', {
                appId: info.claims?.azp || info.claims?.appid || '',
                scopes: info.scopes,
                source
            });
        }

        if (publish) {
            if (window.top === window) broadcastTokenFromTop(info.token, source);
            else sendTokenToTop(info.token, source);
        }
        return true;
    }

    function installTokenBridge() {
        window.addEventListener('message', event => {
            const data = event.data;

            // Portal auth/RPC messages are not necessarily our bridge messages. Inspect
            // allowed Microsoft portal origins for access-token-shaped values before
            // applying the private bridge marker filter.
            if (isAllowedBridgeOrigin(event.origin)) {
                try { collectTokensFromObject(data, `message:${event.origin}`); } catch { /* ignore */ }
            }

            if (!data || data.marker !== TOKEN_BRIDGE_MARKER || !isAllowedBridgeOrigin(event.origin)) return;

            if (window.top === window) {
                if (event.source && event.source !== window) addBridgeClient(event.source, event.origin);

                if (data.type === 'request') {
                    for (const entry of TOKEN_POOL.values()) {
                        try {
                            event.source?.postMessage({
                                marker: TOKEN_BRIDGE_MARKER,
                                type: 'token',
                                token: entry.token,
                                source: 'Intune shell token pool'
                            }, event.origin);
                        } catch { /* ignore */ }
                    }
                    return;
                }

                if (data.type === 'warm-intune-token') {
                    warmIntuneExtensionInTop().catch(e => warn('Intune extension warm-up failed', e));
                    return;
                }

                if (data.type === 'token' && data.token) {
                    const wasAdded = addGraphToken(data.token, `bridge:${data.source || event.origin}`, false);
                    if (wasAdded) broadcastTokenFromTop(normalizeToken(data.token), data.source || event.origin);
                }
                return;
            }

            if (event.source === window.top && event.origin === 'https://intune.microsoft.com' && data.type === 'token' && data.token) {
                addGraphToken(data.token, `bridge:${data.source || 'Intune shell'}`, false);
            }
        }, true);

        if (window.top !== window) {
            try {
                window.top.postMessage({ marker: TOKEN_BRIDGE_MARKER, type: 'request' }, 'https://intune.microsoft.com');
            } catch { /* ignore */ }
        }
    }

    function collectTokensFromObject(value, source, depth = 0, seen = new WeakSet()) {
        if (depth > 10 || value == null) return;

        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (/^Bearer\s+eyJ/i.test(trimmed) || /^eyJ[^.]+\.[^.]+\./.test(trimmed)) {
                addGraphToken(trimmed, source);
            }
            return;
        }

        if (typeof value !== 'object') return;
        try {
            if (seen.has(value)) return;
            seen.add(value);
        } catch { /* non-standard object */ }

        try {
            if (String(value.credentialType || '').toLowerCase() === 'accesstoken' && typeof value.secret === 'string') {
                addGraphToken(value.secret, `${source}:MSAL AccessToken`);
            }
        } catch { /* ignore */ }

        try {
            if (typeof value.authHeader === 'string') addGraphToken(value.authHeader, `${source}:authHeader`);
        } catch { /* ignore */ }

        let entries = [];
        try { entries = Object.entries(value); } catch { return; }
        for (const [key, child] of entries) {
            if (key === 'secret' && typeof child === 'string') {
                try {
                    if (String(value.credentialType || '').toLowerCase() === 'accesstoken') addGraphToken(child, `${source}:secret`);
                } catch { /* ignore */ }
            }
            collectTokensFromObject(child, `${source}.${key}`, depth + 1, seen);
        }
    }

    // Azure Portal ReactViews use RPC/message channels in addition to ordinary fetch/XHR.
    // Capture only access-token-shaped strings that the portal itself transports; the
    // script never reads or redeems refresh tokens.
    function installPortalRpcCapture() {
        let page;
        try { page = unsafeWindow || window; } catch { page = window; }

        try {
            const proto = page.Window?.prototype;
            if (proto?.postMessage && !proto.postMessage.__tmIntuneGroupAssignmentsRpcHookedV14) {
                const original = proto.postMessage;
                const wrapped = function (message, ...rest) {
                    try { collectTokensFromObject(message, 'Window.postMessage'); } catch { /* ignore */ }
                    return Reflect.apply(original, this, [message, ...rest]);
                };
                wrapped.__tmIntuneGroupAssignmentsRpcHookedV14 = true;
                proto.postMessage = wrapped;
            }
        } catch (e) {
            log('Could not hook Window.postMessage', e);
        }

        try {
            const proto = page.MessagePort?.prototype;
            if (proto?.postMessage && !proto.postMessage.__tmIntuneGroupAssignmentsRpcHookedV14) {
                const original = proto.postMessage;
                const wrapped = function (message, ...rest) {
                    try { collectTokensFromObject(message, 'MessagePort.postMessage'); } catch { /* ignore */ }
                    return Reflect.apply(original, this, [message, ...rest]);
                };
                wrapped.__tmIntuneGroupAssignmentsRpcHookedV14 = true;
                proto.postMessage = wrapped;
            }
        } catch (e) {
            log('Could not hook MessagePort.postMessage', e);
        }
    }

    let INTUNE_WARMUP_PROMISE = null;

    function hasUsableIntuneToken() {
        scanSessionStorage();
        purgeExpiredTokens();
        return [...TOKEN_POOL.values()].some(entry =>
            entry.info.graphAudience && !entry.info.expired && entry.info.intuneLike
        );
    }

    function sleepLocal(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function waitForIntuneToken(maxWaitMs = 14000) {
        const until = Date.now() + maxWaitMs;
        while (Date.now() < until) {
            if (hasUsableIntuneToken()) return true;
            await sleepLocal(250);
        }
        return hasUsableIntuneToken();
    }

    async function warmIntuneExtensionInTop() {
        if (hasUsableIntuneToken()) return true;
        if (window.top !== window || location.origin !== 'https://intune.microsoft.com') return false;
        if (INTUNE_WARMUP_PROMISE) return INTUNE_WARMUP_PROMISE;

        INTUNE_WARMUP_PROMISE = (async () => {
            info('No Intune token is currently visible on the AAD group blade. Starting native Intune extension warm-up.');

            let iframe = document.getElementById('tm-iga-intune-token-warmup');
            let created = false;
            if (!iframe) {
                iframe = document.createElement('iframe');
                iframe.id = 'tm-iga-intune-token-warmup';
                iframe.setAttribute('aria-hidden', 'true');
                iframe.setAttribute('tabindex', '-1');
                iframe.style.cssText = [
                    'position:fixed',
                    'left:-10000px',
                    'top:-10000px',
                    'width:8px',
                    'height:8px',
                    'opacity:0',
                    'pointer-events:none',
                    'border:0'
                ].join(';');

                // This is a normal Intune admin-center route. Loading it makes the
                // Microsoft_Intune_DeviceSettings extension request its own Graph token
                // through the portal authentication service, exactly as when the admin
                // navigates to Devices manually.
                iframe.src = 'https://intune.microsoft.com/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu';
                (document.body || document.documentElement).appendChild(iframe);
                created = true;
            }

            try {
                const ok = await waitForIntuneToken(16000);
                if (ok) info('Intune Graph token became available after native extension warm-up.');
                else warn('Native Intune extension warm-up finished without exposing an Intune Graph token.');
                return ok;
            } finally {
                if (created) {
                    try { iframe.remove(); } catch { /* ignore */ }
                }
                INTUNE_WARMUP_PROMISE = null;
            }
        })();

        return INTUNE_WARMUP_PROMISE;
    }

    async function ensureIntuneTokenAvailable() {
        if (hasUsableIntuneToken()) return true;

        if (window.top === window && location.origin === 'https://intune.microsoft.com') {
            return warmIntuneExtensionInTop();
        }

        // Group Overview runs in a Microsoft_AAD_IAM ReactBlade. Ask the top-level
        // Intune shell to warm its own native extension, then wait for the existing
        // token bridge to publish the resulting Graph token back to this frame.
        try {
            window.top.postMessage({
                marker: TOKEN_BRIDGE_MARKER,
                type: 'warm-intune-token'
            }, 'https://intune.microsoft.com');
        } catch { /* ignore */ }

        return waitForIntuneToken(17000);
    }

    function scanSessionStorage() {
        let page;
        try { page = unsafeWindow || window; } catch { page = window; }

        try {
            const storage = page.sessionStorage;
            for (let i = 0; i < storage.length; i++) {
                const key = storage.key(i);
                if (!key) continue;
                const raw = storage.getItem(key);
                if (!raw) continue;
                if (!/AccessToken|authHeader|eyJ/i.test(raw)) continue;

                // MSAL stores AccessToken records as JSON. Azure portal auth bootstrap
                // state can also be stored as nested JSON containing authHeader values.
                try {
                    collectTokensFromObject(JSON.parse(raw), `sessionStorage:${key}`);
                } catch {
                    collectTokensFromObject(raw, `sessionStorage:${key}`);
                }
            }
        } catch (e) {
            log('sessionStorage token scan failed', e);
        }

        // The Azure portal shell exposes its already restored authentication state
        // here. The supplied portal HTML shows authBootstrapState containing oAuthToken,
        // selfOAuthToken and prefetchedTokens; scan only that bounded object.
        try {
            if (page.MsPortalEarly?.authBootstrapState) {
                collectTokensFromObject(page.MsPortalEarly.authBootstrapState, 'MsPortalEarly.authBootstrapState');
            }
        } catch (e) {
            log('Portal bootstrap token scan failed', e);
        }
    }

    function installGraphCapture() {
        let page;
        try { page = unsafeWindow || window; } catch { page = window; }

        try {
            if (page.fetch && !page.fetch.__tmIntuneGroupAssignmentsHookedV14) {
                const originalFetch = page.fetch;
                const wrappedFetch = function (...args) {
                    try {
                        const input = args[0];
                        const init = args[1] || {};
                        const url = normalizeUrl(input);
                        let auth = authFromHeaders(init.headers, page);
                        if (!auth && input?.headers) auth = authFromHeaders(input.headers, page);
                        if (auth) addGraphToken(auth, `fetch:${url}`);
                    } catch (e) {
                        log('fetch token capture failed', e);
                    }
                    return Reflect.apply(originalFetch, this, args);
                };
                wrappedFetch.__tmIntuneGroupAssignmentsHookedV14 = true;
                page.fetch = wrappedFetch;
            }
        } catch (e) {
            log('Could not hook fetch', e);
        }

        try {
            const proto = page.XMLHttpRequest?.prototype;
            if (proto && !proto.__tmIntuneGroupAssignmentsHookedV14) {
                const originalOpen = proto.open;
                const originalSetHeader = proto.setRequestHeader;

                proto.open = function (method, url, ...rest) {
                    try { this.__tmIntuneGroupAssignmentsUrlV14 = normalizeUrl(url); } catch { /* ignore */ }
                    return Reflect.apply(originalOpen, this, [method, url, ...rest]);
                };

                proto.setRequestHeader = function (name, value) {
                    try {
                        if (String(name).toLowerCase() === 'authorization') {
                            addGraphToken(String(value || ''), `xhr:${this.__tmIntuneGroupAssignmentsUrlV14 || ''}`);
                        }
                    } catch (e) {
                        log('XHR token capture failed', e);
                    }
                    return Reflect.apply(originalSetHeader, this, [name, value]);
                };

                proto.__tmIntuneGroupAssignmentsHookedV14 = true;
            }
        } catch (e) {
            log('Could not hook XMLHttpRequest', e);
        }
    }

    function purgeExpiredTokens() {
        for (const [key, entry] of TOKEN_POOL.entries()) {
            const current = inspectToken(entry.token);
            if (!current.claims || current.expired || !current.graphAudience) TOKEN_POOL.delete(key);
            else entry.info = current;
        }
    }

    function scoreTokenForUrl(entry, url) {
        const info = entry.info;
        let score = info.score;
        const lower = String(url || '').toLowerCase();

        if (lower.includes('/deviceappmanagement/')) score += info.apps ? 100000 : 0;
        if (/devicemanagementscripts|devicehealthscripts|deviceshellscripts|devicecustomattributeshellscripts/i.test(lower)) {
            score += info.scripts ? 100000 : 0;
        }
        if (lower.includes('/devicemanagement/')) {
            if (info.configuration) score += 80000;
            if (info.service) score += 30000;
            if (info.managedDevices) score += 10000;
        }
        if (lower.includes('/virtualendpoint/')) score += info.cloudPc ? 100000 : 0;

        return score;
    }

    function getCandidateTokens(url = '') {
        scanSessionStorage();
        purgeExpiredTokens();
        return [...TOKEN_POOL.values()]
            .filter(entry => entry.info.graphAudience && !entry.info.expired && entry.info.intuneLike)
            .sort((a, b) => scoreTokenForUrl(b, url) - scoreTokenForUrl(a, url));
    }

    function getTokenDiagnostics() {
        purgeExpiredTokens();
        return [...TOKEN_POOL.values()].map(entry => ({
            appId: entry.info.claims?.azp || entry.info.claims?.appid || '',
            aud: entry.info.claims?.aud || '',
            scopes: entry.info.scopes,
            intuneLike: entry.info.intuneLike,
            score: entry.info.score,
            sources: [...entry.sources].slice(0, 3)
        }));
    }

    installPortalRpcCapture();
    installTokenBridge();
    installGraphCapture();
    scanSessionStorage();
    setTimeout(scanSessionStorage, 250);
    setTimeout(scanSessionStorage, 1000);
    setInterval(scanSessionStorage, 5000);
    window.addEventListener('focus', scanSessionStorage, true);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) scanSessionStorage();
    });

    // -------------------------------------------------------------------------
    // Graph client
    // -------------------------------------------------------------------------

    class GraphError extends Error {
        constructor(message, status = 0, body = null, url = '') {
            super(message);
            this.name = 'GraphError';
            this.status = status;
            this.body = body;
            this.url = url;
        }
    }

    function gmRequest({ method = 'GET', url, headers = {}, data = null, timeout = 60000 }) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method,
                url,
                headers,
                data,
                timeout,
                onload: resolve,
                onerror: err => reject(new Error(`Network error: ${err?.error || err?.statusText || 'unknown error'}`)),
                ontimeout: () => reject(new Error(`Request timed out: ${url}`))
            });
        });
    }

    function parseJsonSafe(text) {
        if (!text) return null;
        try { return JSON.parse(text); } catch { return null; }
    }

    function isTokenAuthorizationFailure(status, message) {
        if (status === 401) return true;
        if (status !== 403) return false;
        return /not authorized|authorization_requestdenied|insufficient privileges|must have one of the following scopes|forbidden/i.test(String(message || ''));
    }

    function formatTokenDiag(entry) {
        const appId = entry?.info?.claims?.azp || entry?.info?.claims?.appid || '(unknown appId)';
        const scopes = entry?.info?.scopes?.filter(s => /^DeviceManagement|^CloudPC/i.test(s)) || [];
        return `${appId} [${scopes.join(', ') || 'no DeviceManagement scopes'}]`;
    }

    async function graphRequest(method, urlOrPath, body = null, retry = 0) {
        const url = /^https?:\/\//i.test(urlOrPath) ? urlOrPath : `${GRAPH_ROOT}${urlOrPath}`;
        let candidates = getCandidateTokens(url);

        if (!candidates.length) {
            await ensureIntuneTokenAvailable();
            candidates = getCandidateTokens(url);
        }

        if (!candidates.length) {
            const discovered = getTokenDiagnostics();
            const graphOnly = discovered.length
                ? discovered.map(d => `${d.appId || '(unknown)'}: ${d.scopes.join(', ') || '(no readable scopes)'}`).join(' | ')
                : 'none';
            throw new GraphError(
                `No Intune-capable Microsoft Graph token is available. v1.4 checked MSAL sessionStorage, Azure portal authBootstrapState, fetch/XHR, portal postMessage/MessagePort RPC and the cross-frame bridge, and it requested a native Microsoft_Intune_DeviceSettings warm-up. Microsoft Graph tokens currently discovered: ${graphOnly}`,
                401,
                null,
                url
            );
        }

        let lastFailure = null;
        for (let index = 0; index < candidates.length; index++) {
            const entry = candidates[index];
            const headers = {
                Authorization: `Bearer ${entry.token}`,
                Accept: 'application/json',
                'Content-Type': 'application/json'
            };

            const response = await gmRequest({
                method,
                url,
                headers,
                data: body == null ? null : JSON.stringify(body)
            });

            const parsed = parseJsonSafe(response.responseText);
            const status = Number(response.status || 0);
            if (status >= 200 && status < 300) return parsed ?? {};

            const message = parsed?.error?.message || parsed?.message || response.statusText || `HTTP ${status}`;

            if ((status === 429 || status === 503 || status === 504) && retry < 3) {
                let retryAfter = 0;
                try {
                    const match = String(response.responseHeaders || '').match(/^retry-after:\s*(\d+)/im);
                    retryAfter = match ? Number(match[1]) * 1000 : 0;
                } catch { /* ignore */ }
                await sleep(retryAfter || (1000 * Math.pow(2, retry)));
                return graphRequest(method, url, body, retry + 1);
            }

            lastFailure = new GraphError(
                `${message} | Token ${index + 1}/${candidates.length}: ${formatTokenDiag(entry)}`,
                status,
                parsed,
                url
            );

            // This is the behavior used by the other working scripts: do not assume
            // the first Graph token is the right one. Try the next in-memory token on
            // authorization failures.
            if (isTokenAuthorizationFailure(status, message) && index + 1 < candidates.length) {
                log(`Token ${index + 1} rejected for ${url}; trying next token.`, formatTokenDiag(entry));
                continue;
            }

            throw lastFailure;
        }

        throw lastFailure || new GraphError('Microsoft Graph request failed.', 0, null, url);
    }

    async function graphGetAll(urlOrPath) {
        const results = [];
        let next = urlOrPath;
        let pages = 0;

        while (next) {
            if (++pages > 1000) throw new Error(`Pagination safety limit reached for ${urlOrPath}`);
            const response = await graphRequest('GET', next);
            if (Array.isArray(response?.value)) results.push(...response.value);
            else if (response && response.id) results.push(response);
            next = response?.['@odata.nextLink'] || null;
        }
        return results;
    }

    function toBatchRelativeUrl(path) {
        let url = path;
        if (/^https?:\/\//i.test(url)) {
            const parsed = new URL(url);
            url = `${parsed.pathname}${parsed.search}`;
        }
        url = url.replace(/^\/beta/i, '').replace(/^\/v1\.0/i, '');
        return url.startsWith('/') ? url : `/${url}`;
    }

    async function graphBatchGet(requests) {
        const output = new Map();
        const chunks = [];
        for (let i = 0; i < requests.length; i += 20) chunks.push(requests.slice(i, i + 20));

        for (const chunk of chunks) {
            const payload = {
                requests: chunk.map((r, index) => ({
                    id: String(index + 1),
                    method: 'GET',
                    url: toBatchRelativeUrl(r.url),
                    headers: { Accept: 'application/json' }
                }))
            };

            const response = await graphRequest('POST', '/beta/$batch', payload);
            const byId = new Map((response?.responses || []).map(r => [String(r.id), r]));

            for (let index = 0; index < chunk.length; index++) {
                const request = chunk[index];
                const item = byId.get(String(index + 1));
                if (!item) {
                    output.set(request.key, { ok: false, status: 0, error: 'Missing response in Graph batch.' });
                    continue;
                }

                if (item.status >= 200 && item.status < 300) {
                    const values = Array.isArray(item.body?.value) ? [...item.body.value] : [];
                    let next = item.body?.['@odata.nextLink'] || null;
                    try {
                        while (next) {
                            const page = await graphRequest('GET', next);
                            if (Array.isArray(page?.value)) values.push(...page.value);
                            next = page?.['@odata.nextLink'] || null;
                        }
                        output.set(request.key, { ok: true, status: item.status, value: values });
                    } catch (e) {
                        output.set(request.key, { ok: false, status: e.status || 0, error: e.message });
                    }
                } else {
                    output.set(request.key, {
                        ok: false,
                        status: item.status,
                        error: item.body?.error?.message || `HTTP ${item.status}`
                    });
                }
            }
        }

        return output;
    }

    async function getAssignmentFilters() {
        const map = new Map();
        try {
            const filters = await graphGetAll('/beta/deviceManagement/assignmentFilters?$select=id,displayName,platform,rule');
            for (const filter of filters) map.set(String(filter.id).toLowerCase(), filter);
        } catch (e) {
            log('Assignment filters could not be loaded', e);
        }
        return map;
    }

    // -------------------------------------------------------------------------
    // Assignment parsing
    // -------------------------------------------------------------------------

    function getObjectName(item) {
        return item?.displayName || item?.name || item?.localizedDisplayName || item?.title || item?.id || '(unnamed)';
    }

    function getModified(item) {
        return item?.lastModifiedDateTime || item?.modifiedDateTime || item?.createdDateTime || '';
    }

    function getTargetGroupId(target) {
        return String(target?.groupId || target?.entraObjectId || '').toLowerCase();
    }

    function getAssignmentMode(target) {
        const odata = String(target?.['@odata.type'] || '').toLowerCase();
        if (odata.includes('exclusiongroupassignmenttarget')) return 'Exclude';
        if (odata.includes('groupassignmenttarget')) return 'Include';
        return '';
    }

    function getFilterInfo(target, filterMap) {
        const id = String(target?.deviceAndAppManagementAssignmentFilterId || '').trim();
        const filterTypeRaw = String(target?.deviceAndAppManagementAssignmentFilterType || '').trim();
        const filterType = /exclude/i.test(filterTypeRaw) ? 'Exclude' : /include/i.test(filterTypeRaw) ? 'Include' : '';
        if (!id || /^0{8}-0{4}-0{4}-0{4}-0{12}$/i.test(id)) {
            return { id: '', name: '', mode: filterType };
        }
        const filter = filterMap.get(id.toLowerCase());
        return {
            id,
            name: filter?.displayName || id,
            mode: filterType,
            platform: filter?.platform || '',
            rule: filter?.rule || ''
        };
    }

    function assignmentToRecord(workload, item, assignment, groupId, filterMap) {
        const target = assignment?.target || {};
        if (getTargetGroupId(target) !== groupId.toLowerCase()) return null;
        const mode = getAssignmentMode(target);
        if (!mode) return null;

        const filter = getFilterInfo(target, filterMap);
        return {
            name: getObjectName(item),
            type: workload.type,
            mode,
            intent: assignment?.intent || assignment?.targetType || '',
            filterName: filter.name || '',
            filterMode: filter.mode || '',
            filterId: filter.id || '',
            filterRule: filter.rule || '',
            id: String(item?.id || ''),
            assignmentId: String(assignment?.id || ''),
            modified: getModified(item),
            odataType: String(item?.['@odata.type'] || '').replace(/^#microsoft\.graph\./i, '')
        };
    }

    function collectRecords(workload, item, assignments, groupId, filterMap) {
        const records = [];
        for (const assignment of assignments || []) {
            const record = assignmentToRecord(workload, item, assignment, groupId, filterMap);
            if (record) records.push(record);
        }
        return records;
    }

    async function scanViaExpand(workload, groupId, filterMap) {
        const join = workload.path.includes('?') ? '&' : '?';
        const expandedPath = `${workload.path}${join}$expand=assignments`;
        let items;

        try {
            items = await graphGetAll(expandedPath);
        } catch (expandError) {
            log(`Expand failed for ${workload.type}; falling back to batch`, expandError);
            return scanViaBatch(workload, groupId, filterMap);
        }

        const records = [];
        const continuation = [];
        for (const item of items) {
            let assignments = Array.isArray(item.assignments) ? item.assignments : [];
            records.push(...collectRecords(workload, item, assignments, groupId, filterMap));

            const next = item?.['assignments@odata.nextLink'];
            if (next) continuation.push({ item, next });
        }

        for (const entry of continuation) {
            try {
                const more = await graphGetAll(entry.next);
                records.push(...collectRecords(workload, entry.item, more, groupId, filterMap));
            } catch (e) {
                log('Expanded assignment continuation failed', workload.type, e);
            }
        }
        return records;
    }

    async function scanViaBatch(workload, groupId, filterMap) {
        const items = await graphGetAll(workload.path);
        const requests = items.map(item => ({
            key: String(item.id),
            url: `${workload.path.split('?')[0]}/${encodeURIComponent(item.id)}/assignments`
        }));
        const responseMap = await graphBatchGet(requests);

        const records = [];
        for (const item of items) {
            const response = responseMap.get(String(item.id));
            if (!response?.ok) continue;
            records.push(...collectRecords(workload, item, response.value, groupId, filterMap));
        }
        return records;
    }

    function appProtectionAssignmentPath(item) {
        const type = String(item?.['@odata.type'] || '').toLowerCase();
        const id = encodeURIComponent(item.id);
        if (type.includes('androidmanagedappprotection')) return `/beta/deviceAppManagement/androidManagedAppProtections('${id}')/assignments`;
        if (type.includes('iosmanagedappprotection')) return `/beta/deviceAppManagement/iosManagedAppProtections('${id}')/assignments`;
        if (type.includes('windowsinformationprotectionapplockerfileprotection')) return `/beta/deviceAppManagement/windowsInformationProtectionAppLockerFileProtections('${id}')/assignments`;
        if (type.includes('windowsmanagedappprotection')) return `/beta/deviceAppManagement/windowsManagedAppProtections('${id}')/assignments`;
        if (type.includes('targetedmanagedappconfiguration')) return `/beta/deviceAppManagement/targetedManagedAppConfigurations('${id}')/assignments`;
        return '';
    }

    async function scanAppProtection(workload, groupId, filterMap) {
        const items = await graphGetAll(workload.path);
        const requests = [];
        for (const item of items) {
            const url = appProtectionAssignmentPath(item);
            if (url) requests.push({ key: String(item.id), url });
        }
        const responseMap = await graphBatchGet(requests);

        const records = [];
        for (const item of items) {
            const response = responseMap.get(String(item.id));
            if (!response?.ok) continue;
            records.push(...collectRecords(workload, item, response.value, groupId, filterMap));
        }
        return records;
    }

    async function scanWorkload(workload, groupId, filterMap) {
        if (workload.strategy === 'batch') return scanViaBatch(workload, groupId, filterMap);
        if (workload.strategy === 'appProtection') return scanAppProtection(workload, groupId, filterMap);
        return scanViaExpand(workload, groupId, filterMap);
    }

    async function mapLimit(items, limit, worker) {
        const result = new Array(items.length);
        let next = 0;
        const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
            while (true) {
                const index = next++;
                if (index >= items.length) return;
                result[index] = await worker(items[index], index);
            }
        });
        await Promise.all(runners);
        return result;
    }

    async function scanAllAssignments(groupId, onProgress) {
        const filterMap = await getAssignmentFilters();
        const errors = [];
        const records = [];
        let completed = 0;

        await mapLimit(WORKLOADS, 3, async workload => {
            onProgress?.({ completed, total: WORKLOADS.length, current: workload.type });
            try {
                const found = await scanWorkload(workload, groupId, filterMap);
                records.push(...found);
            } catch (e) {
                const authFailure = e?.status === 401;
                errors.push({
                    type: workload.type,
                    status: e?.status || 0,
                    message: e?.message || String(e),
                    optional: Boolean(workload.optional)
                });
                if (authFailure) throw e;
            } finally {
                completed++;
                onProgress?.({ completed, total: WORKLOADS.length, current: workload.type });
            }
        });

        // One assignment should only occur once, but de-duplicate defensively.
        const dedupe = new Map();
        for (const record of records) {
            const key = [record.type, record.id, record.assignmentId, record.mode, record.intent].join('|').toLowerCase();
            dedupe.set(key, record);
        }

        const sorted = [...dedupe.values()].sort((a, b) =>
            a.type.localeCompare(b.type, undefined, { sensitivity: 'base' }) ||
            a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) ||
            a.mode.localeCompare(b.mode)
        );

        return { records: sorted, errors };
    }

    // -------------------------------------------------------------------------
    // Group detection
    // -------------------------------------------------------------------------

    function getGroupInfoFromDom() {
        // Most reliable source in the current Entra group overview ReactView.
        const labels = [...document.querySelectorAll('label')];
        const objectIdLabel = labels.find(label => /^object id$/i.test(label.textContent.trim()));
        let id = '';

        if (objectIdLabel) {
            let scope = objectIdLabel.parentElement;
            for (let i = 0; i < 4 && scope; i++, scope = scope.parentElement) {
                const match = scope.innerText?.match(GUID_RE);
                if (match) { id = match[0]; break; }
            }
        }

        if (!id) {
            const locationMatch = `${location.href}${document.referrer || ''}`.match(/groupId[\/=]([0-9a-f-]{36})/i);
            if (locationMatch && GUID_RE.test(locationMatch[1])) id = locationMatch[1];
        }

        if (!id) return null;

        let name = '';
        const titledGroupIcon = [...document.querySelectorAll('[title]')].find(el => {
            const title = String(el.getAttribute('title') || '').trim();
            return title && !GUID_RE.test(title) && el.classList.contains('ext-grid-icon');
        });
        if (titledGroupIcon) name = titledGroupIcon.getAttribute('title').trim();

        if (!name) {
            const headingCandidates = [...document.querySelectorAll('h1,h2,h3,.textStyle-149')]
                .map(el => el.textContent.trim())
                .filter(Boolean)
                .filter(text => !/^(basic information|feed|overview)$/i.test(text));
            name = headingCandidates.find(text => !GUID_RE.test(text) && text.length < 180) || '';
        }

        return { id: id.toLowerCase(), name: name || 'Current group' };
    }

    function isGroupOverviewBlade() {
        if (!document.body) return false;
        const info = getGroupInfoFromDom();
        if (!info) return false;
        const hasOverview = [...document.querySelectorAll('[role="tab"],button')]
            .some(el => /^overview$/i.test(String(el.getAttribute('name') || el.getAttribute('data-content') || el.textContent || '').trim()));
        return hasOverview;
    }

    // -------------------------------------------------------------------------
    // UI
    // -------------------------------------------------------------------------

    function addStyle() {
        if (document.getElementById(`${SCRIPT_ID}-style`)) return;
        const style = document.createElement('style');
        style.id = `${SCRIPT_ID}-style`;
        style.textContent = `
            #${SCRIPT_ID}-button { cursor: pointer !important; }
            #${SCRIPT_ID}-overlay {
                position: fixed; inset: 0; z-index: 320000; display: flex; align-items: center; justify-content: center;
                padding: 24px; box-sizing: border-box; background: rgba(0,0,0,.38); font-family: "Segoe UI", sans-serif;
            }
            #${SCRIPT_ID}-dialog {
                width: min(1500px, calc(100vw - 48px)); height: min(860px, calc(100vh - 48px));
                display: flex; flex-direction: column; overflow: hidden;
                background: var(--colorContainerBackgroundPrimary, #fff); color: var(--colorTextPrimary, #323130);
                border: 1px solid var(--colorContainerBorderSecondary, #d2d0ce); box-shadow: var(--shadowLevel4, 0 25px 58px rgba(0,0,0,.32));
            }
            .tm-iga-titlebar { display:flex; align-items:center; gap:12px; min-height:58px; padding:0 18px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-iga-title-wrap { min-width:0; flex:1; }
            .tm-iga-title { margin:0; font-size:20px; font-weight:600; line-height:26px; }
            .tm-iga-subtitle { margin-top:2px; font-size:12px; color:var(--colorTextSecondary,#605e5c); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
            .tm-iga-icon-btn, .tm-iga-secondary-btn { height:32px; border:0; background:transparent; color:var(--colorTextPrimary,#323130); cursor:pointer; font:13px "Segoe UI",sans-serif; }
            .tm-iga-icon-btn { width:34px; font-size:18px; }
            .tm-iga-secondary-btn { padding:0 10px; border:1px solid var(--colorControlBorder,#8a8886); }
            .tm-iga-secondary-btn:hover, .tm-iga-icon-btn:hover { background:var(--colorControlBackgroundHover,#f3f2f1); }
            .tm-iga-toolbar { display:flex; gap:10px; align-items:center; padding:12px 18px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); flex-wrap:wrap; }
            .tm-iga-search { flex:1 1 320px; min-width:220px; height:32px; box-sizing:border-box; padding:0 10px; border:1px solid var(--colorControlBorder,#8a8886); background:var(--colorControlBackground,#fff); color:var(--colorTextPrimary,#323130); outline:none; }
            .tm-iga-select { height:32px; min-width:160px; padding:0 8px; border:1px solid var(--colorControlBorder,#8a8886); background:var(--colorControlBackground,#fff); color:var(--colorTextPrimary,#323130); }
            .tm-iga-summary { display:flex; gap:16px; align-items:center; min-height:36px; padding:0 18px; font-size:12px; color:var(--colorTextSecondary,#605e5c); border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); }
            .tm-iga-progress { height:3px; background:var(--colorContainerBackgroundSecondary,#f3f2f1); overflow:hidden; }
            .tm-iga-progress > div { height:100%; width:0; background:var(--colorControlBackgroundBrand,#0078d4); transition:width .15s ease; }
            .tm-iga-table-wrap { flex:1; min-height:0; overflow:auto; }
            .tm-iga-table { width:100%; border-collapse:collapse; table-layout:fixed; font-size:13px; }
            .tm-iga-table th { position:sticky; top:0; z-index:2; text-align:left; font-size:12px; font-weight:600; color:var(--colorTextSecondary,#605e5c); background:var(--colorContainerBackgroundPrimary,#fff); border-bottom:1px solid var(--colorContainerBorderSecondary,#d2d0ce); padding:9px 10px; }
            .tm-iga-table td { padding:8px 10px; border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle; }
            .tm-iga-table tbody tr:hover { background:var(--todoFocusRowHover,var(--colorControlBackgroundHover,#f3f2f1)); }
            .tm-iga-col-name { width:31%; } .tm-iga-col-type { width:20%; } .tm-iga-col-mode { width:8%; } .tm-iga-col-intent { width:9%; } .tm-iga-col-filter { width:16%; } .tm-iga-col-date { width:11%; } .tm-iga-col-id { width:5%; }
            .tm-iga-badge { display:inline-block; min-width:54px; padding:2px 7px; box-sizing:border-box; text-align:center; border-radius:10px; font-size:11px; font-weight:600; }
            .tm-iga-badge-include { background:rgba(16,124,16,.15); color:var(--colorTextSuccess,#107c10); }
            .tm-iga-badge-exclude { background:rgba(209,52,56,.15); color:var(--colorTextError,#d13438); }
            .tm-iga-linklike { color:var(--colorLink,#0078d4); cursor:pointer; text-decoration:none; }
            .tm-iga-empty { padding:50px 18px; text-align:center; color:var(--colorTextSecondary,#605e5c); }
            .tm-iga-status { padding:16px 18px; font-size:13px; color:var(--colorTextSecondary,#605e5c); }
            .tm-iga-errors { flex:0 0 auto; max-height:145px; overflow:auto; border-top:1px solid var(--colorContainerBorderPrimary,#edebe9); padding:8px 18px; font-size:12px; color:var(--colorTextSecondary,#605e5c); }
            .tm-iga-error-line { padding:2px 0; }
            @media (max-width:900px) {
                #${SCRIPT_ID}-overlay { padding:8px; }
                #${SCRIPT_ID}-dialog { width:calc(100vw - 16px); height:calc(100vh - 16px); }
                .tm-iga-col-date, .tm-iga-col-id { display:none; }
            }
        `;
        (document.head || document.documentElement).appendChild(style);
    }

    function createCommandButton() {
        if (!isGroupOverviewBlade()) return;
        if (document.getElementById(`${SCRIPT_ID}-button`)) return;

        const primary = document.querySelector('#__bladeCommandBar .ms-CommandBar-primaryCommand') ||
                        document.querySelector('#__bladeCommandBar [role="menubar"]');
        if (!primary) return;

        const item = document.createElement('div');
        item.className = 'ms-OverflowSet-item';
        item.setAttribute('role', 'none');
        item.innerHTML = `
            <button id="${SCRIPT_ID}-button" type="button" role="menuitem"
                    class="ms-Button ms-Button--commandBar ms-CommandBarItem-link"
                    aria-label="Show Intune assignments" title="Show all Intune assignments for this group">
                <span class="ms-Button-flexContainer" style="display:flex;align-items:center;gap:7px;">
                    <span aria-hidden="true" style="font-size:17px;line-height:1;">☷</span>
                    <span class="ms-Button-textContainer"><span class="ms-Button-label">Intune assignments</span></span>
                </span>
            </button>`;
        primary.appendChild(item);
        item.querySelector('button').addEventListener('click', openDialog);
        document.documentElement.dataset.tmIntuneGroupAssignments = 'active';
    }

    function formatDate(value) {
        if (!value) return '';
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) return String(value);
        return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }).format(d);
    }

    function csvEscape(value) {
        const text = String(value ?? '');
        return `"${text.replace(/"/g, '""')}"`;
    }

    function exportCsv(group, records) {
        const header = ['Group','GroupId','Assignment','Type','Mode','Intent','Filter','FilterMode','ObjectId','AssignmentId','Modified'];
        const rows = [header.map(csvEscape).join(';')];
        for (const r of records) {
            rows.push([
                group.name, group.id, r.name, r.type, r.mode, r.intent,
                r.filterName, r.filterMode, r.id, r.assignmentId, r.modified
            ].map(csvEscape).join(';'));
        }
        const blob = new Blob(['\uFEFF', rows.join('\r\n')], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const safeName = group.name.replace(/[\\/:*?"<>|]+/g, '_').slice(0, 100);
        a.href = url;
        a.download = `Intune-Assignments-${safeName || group.id}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
    }

    function closeDialog() {
        document.getElementById(`${SCRIPT_ID}-overlay`)?.remove();
    }

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            const area = document.createElement('textarea');
            area.value = text;
            area.style.position = 'fixed';
            area.style.opacity = '0';
            document.body.appendChild(area);
            area.select();
            document.execCommand('copy');
            area.remove();
        }
    }

    function openDialog() {
        const group = getGroupInfoFromDom();
        if (!group) return;
        closeDialog();
        addStyle();

        const overlay = document.createElement('div');
        overlay.id = `${SCRIPT_ID}-overlay`;
        overlay.innerHTML = `
            <section id="${SCRIPT_ID}-dialog" role="dialog" aria-modal="true" aria-label="Intune assignments">
                <div class="tm-iga-titlebar">
                    <div class="tm-iga-title-wrap">
                        <h2 class="tm-iga-title">Intune assignments</h2>
                        <div class="tm-iga-subtitle"></div>
                    </div>
                    <button class="tm-iga-secondary-btn" data-action="refresh">Refresh</button>
                    <button class="tm-iga-secondary-btn" data-action="csv" disabled>Export CSV</button>
                    <button class="tm-iga-icon-btn" data-action="close" aria-label="Close" title="Close">×</button>
                </div>
                <div class="tm-iga-toolbar">
                    <input class="tm-iga-search" type="search" placeholder="Search assignment, type, intent or filter…" disabled>
                    <select class="tm-iga-select tm-iga-type" disabled><option value="">All types</option></select>
                    <select class="tm-iga-select tm-iga-mode" disabled>
                        <option value="">Include + Exclude</option><option value="Include">Include only</option><option value="Exclude">Exclude only</option>
                    </select>
                </div>
                <div class="tm-iga-summary"><span data-summary>Not loaded</span></div>
                <div class="tm-iga-progress"><div></div></div>
                <div class="tm-iga-table-wrap"><div class="tm-iga-status">Loading Intune assignments…</div></div>
                <div class="tm-iga-errors" hidden></div>
            </section>`;
        document.body.appendChild(overlay);

        const subtitle = overlay.querySelector('.tm-iga-subtitle');
        subtitle.textContent = `${group.name}  ·  ${group.id}`;
        subtitle.title = `${group.name}\n${group.id}`;

        overlay.addEventListener('mousedown', event => {
            if (event.target === overlay) closeDialog();
        });
        overlay.querySelector('[data-action="close"]').addEventListener('click', closeDialog);
        document.addEventListener('keydown', function escHandler(event) {
            if (event.key === 'Escape' && document.getElementById(`${SCRIPT_ID}-overlay`)) {
                closeDialog();
                document.removeEventListener('keydown', escHandler);
            }
        });

        const state = { group, records: [], errors: [], loaded: false };
        overlay.querySelector('[data-action="refresh"]').addEventListener('click', () => loadIntoDialog(overlay, state));
        overlay.querySelector('[data-action="csv"]').addEventListener('click', () => exportCsv(state.group, getFilteredRecords(overlay, state.records)));
        overlay.querySelector('.tm-iga-search').addEventListener('input', () => renderRecords(overlay, state));
        overlay.querySelector('.tm-iga-type').addEventListener('change', () => renderRecords(overlay, state));
        overlay.querySelector('.tm-iga-mode').addEventListener('change', () => renderRecords(overlay, state));

        loadIntoDialog(overlay, state);
    }

    function getFilteredRecords(overlay, records) {
        const q = overlay.querySelector('.tm-iga-search').value.trim().toLowerCase();
        const type = overlay.querySelector('.tm-iga-type').value;
        const mode = overlay.querySelector('.tm-iga-mode').value;

        return records.filter(r => {
            if (type && r.type !== type) return false;
            if (mode && r.mode !== mode) return false;
            if (!q) return true;
            return [r.name, r.type, r.mode, r.intent, r.filterName, r.filterMode, r.id, r.odataType]
                .some(v => String(v || '').toLowerCase().includes(q));
        });
    }

    function renderRecords(overlay, state) {
        const wrap = overlay.querySelector('.tm-iga-table-wrap');
        const filtered = getFilteredRecords(overlay, state.records);
        const includeCount = state.records.filter(r => r.mode === 'Include').length;
        const excludeCount = state.records.filter(r => r.mode === 'Exclude').length;
        overlay.querySelector('[data-summary]').textContent =
            `${filtered.length} shown · ${state.records.length} total · ${includeCount} include · ${excludeCount} exclude`;

        if (!filtered.length) {
            wrap.innerHTML = `<div class="tm-iga-empty">No matching direct Intune assignments were found for this group.</div>`;
            return;
        }

        const table = document.createElement('table');
        table.className = 'tm-iga-table';
        table.innerHTML = `
            <thead><tr>
                <th class="tm-iga-col-name">Assignment</th>
                <th class="tm-iga-col-type">Type</th>
                <th class="tm-iga-col-mode">Mode</th>
                <th class="tm-iga-col-intent">Intent</th>
                <th class="tm-iga-col-filter">Assignment filter</th>
                <th class="tm-iga-col-date">Modified</th>
                <th class="tm-iga-col-id">ID</th>
            </tr></thead><tbody></tbody>`;
        const tbody = table.querySelector('tbody');

        for (const r of filtered) {
            const tr = document.createElement('tr');
            const filterText = r.filterName ? `${r.filterName}${r.filterMode ? ` [${r.filterMode}]` : ''}` : '';
            tr.innerHTML = `
                <td class="tm-iga-col-name"></td>
                <td class="tm-iga-col-type"></td>
                <td class="tm-iga-col-mode"><span class="tm-iga-badge tm-iga-badge-${r.mode.toLowerCase()}">${r.mode}</span></td>
                <td class="tm-iga-col-intent"></td>
                <td class="tm-iga-col-filter"></td>
                <td class="tm-iga-col-date"></td>
                <td class="tm-iga-col-id"><a class="tm-iga-linklike" title="Copy object ID">Copy</a></td>`;

            const cells = tr.querySelectorAll('td');
            cells[0].textContent = r.name; cells[0].title = `${r.name}${r.odataType ? `\n${r.odataType}` : ''}`;
            cells[1].textContent = r.type; cells[1].title = r.type;
            cells[3].textContent = r.intent || '—'; cells[3].title = r.intent || '';
            cells[4].textContent = filterText || '—';
            cells[4].title = r.filterRule ? `${filterText}\n${r.filterRule}` : filterText;
            cells[5].textContent = formatDate(r.modified) || '—'; cells[5].title = r.modified || '';
            cells[6].querySelector('a').addEventListener('click', () => copyText(r.id));
            tbody.appendChild(tr);
        }

        wrap.replaceChildren(table);
    }

    function renderErrors(overlay, errors) {
        const box = overlay.querySelector('.tm-iga-errors');
        if (!errors.length) {
            box.hidden = true;
            box.replaceChildren();
            return;
        }

        box.hidden = false;
        const title = document.createElement('div');
        const nonOptional = errors.filter(e => !e.optional).length;
        title.style.fontWeight = '600';
        title.textContent = nonOptional
            ? `${errors.length} workload(s) could not be queried. Results may be incomplete:`
            : `${errors.length} optional workload(s) could not be queried:`;
        box.replaceChildren(title);

        for (const error of errors) {
            const line = document.createElement('div');
            line.className = 'tm-iga-error-line';
            line.textContent = `${error.type}: ${error.status ? `HTTP ${error.status} · ` : ''}${error.message}`;
            box.appendChild(line);
        }
    }

    async function loadIntoDialog(overlay, state) {
        const wrap = overlay.querySelector('.tm-iga-table-wrap');
        const progress = overlay.querySelector('.tm-iga-progress > div');
        const summary = overlay.querySelector('[data-summary]');
        const inputs = overlay.querySelectorAll('.tm-iga-search,.tm-iga-type,.tm-iga-mode,[data-action="csv"]');
        const refresh = overlay.querySelector('[data-action="refresh"]');

        inputs.forEach(el => el.disabled = true);
        refresh.disabled = true;
        progress.style.width = '0%';
        wrap.innerHTML = `<div class="tm-iga-status">Loading Intune assignments…</div>`;
        summary.textContent = 'Preparing Microsoft Graph queries…';
        renderErrors(overlay, []);

        try {
            // Refresh the same token sources used by the other working Intune scripts.
            scanSessionStorage();
            if (!getCandidateTokens('/beta/deviceManagement').length && !getCandidateTokens('/beta/deviceAppManagement').length) {
                const diag = getTokenDiagnostics();
                const found = diag.length
                    ? diag.map(d => `${d.appId || '(unknown)'}: ${d.scopes.join(', ') || '(no readable scopes)'}`).join(' | ')
                    : 'none';
                throw new GraphError(`No Intune-capable Microsoft Graph token is available. Token sources checked: MSAL sessionStorage, Azure portal authBootstrapState, fetch/XHR and cross-frame bridge. Graph tokens discovered: ${found}`, 401);
            }

            const result = await scanAllAssignments(state.group.id, p => {
                const percent = Math.round((p.completed / Math.max(1, p.total)) * 100);
                progress.style.width = `${percent}%`;
                summary.textContent = `${p.completed}/${p.total} workloads queried · ${p.current}`;
            });

            state.records = result.records;
            state.errors = result.errors;
            state.loaded = true;

            const typeSelect = overlay.querySelector('.tm-iga-type');
            const current = typeSelect.value;
            typeSelect.innerHTML = '<option value="">All types</option>';
            for (const type of [...new Set(state.records.map(r => r.type))].sort((a,b) => a.localeCompare(b))) {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                typeSelect.appendChild(option);
            }
            typeSelect.value = [...typeSelect.options].some(o => o.value === current) ? current : '';

            inputs.forEach(el => el.disabled = false);
            renderRecords(overlay, state);
            renderErrors(overlay, state.errors);
            progress.style.width = '100%';
        } catch (e) {
            const status = e?.status ? `HTTP ${e.status}: ` : '';
            wrap.innerHTML = '';
            const error = document.createElement('div');
            error.className = 'tm-iga-status';
            error.style.color = 'var(--colorTextError,#d13438)';
            error.textContent = `${status}${e?.message || String(e)}`;
            wrap.appendChild(error);
            summary.textContent = 'Assignment scan failed';
            progress.style.width = '0%';
        } finally {
            refresh.disabled = false;
        }
    }

    // -------------------------------------------------------------------------
    // Bootstrap / SPA re-render handling
    // -------------------------------------------------------------------------

    let observer;
    function bootstrapUi() {
        if (!document.body) return;
        addStyle();
        createCommandButton();
        if (!observer) {
            observer = new MutationObserver(() => {
                if (isGroupOverviewBlade()) createCommandButton();
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootstrapUi, { once: true });
    } else {
        bootstrapUi();
    }
})();
