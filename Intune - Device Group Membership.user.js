// ==UserScript==
// @name         Intune - Device Group Membership
// @namespace    xento.betterintuneui
// @version      2.7.0
// @description  Adds or removes the current Intune device from multiple Entra groups directly from the group membership view.
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

(function () {
    'use strict';

    const SCRIPT_PREFIX = '[Intune MultiGroup Remove]';
    const MSG_REQUEST_CONTEXT = 'TM_DGM_REQUEST_CONTEXT_V1';
    const MSG_CONTEXT = 'TM_DGM_CONTEXT_V1';
    const MSG_TOKEN = 'TM_DGM_GRAPH_TOKEN_V1';
    const MSG_DEVICE_ID = 'TM_DGM_ENTRA_DEVICE_ID_V1';
    const INTUNE_ORIGIN = 'https://intune.microsoft.com';
    const GRAPH_ORIGIN = 'https://graph.microsoft.com';
    const GRAPH_RESOURCE_APP_ID = '00000003-0000-0000-c000-000000000000';
    const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const MANAGED_DEVICE_RE = /\/groupMembership\/managedDeviceId\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
    const REACTBLADE_HOST_RE = /(^|\.)reactblade(?:-ms|-rc)?\.portal\.azure\.net$/i;
    // Entra/Intune membership changes can take a few seconds to propagate to the
    // membership query used by this blade. Do not refresh the list immediately
    // after a successful Graph mutation, otherwise the old state can be loaded again.
    const GROUP_REFRESH_DELAY_MS = 4000;

    const pageWindow = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
    const tokenStore = [];
    let lastStorageScan = 0;
    let observedEntraDeviceId = null;

    function log(...args) {
        console.log(SCRIPT_PREFIX, ...args);
    }

    function warn(...args) {
        console.warn(SCRIPT_PREFIX, ...args);
    }

    function isReactBladeHost(hostname = location.hostname) {
        return REACTBLADE_HOST_RE.test(hostname);
    }

    function isAllowedReactBladeOrigin(origin) {
        try {
            const url = new URL(origin);
            return url.protocol === 'https:' && isReactBladeHost(url.hostname);
        } catch (_) {
            return false;
        }
    }

    function isGraphUrl(url) {
        try {
            const parsed = new URL(String(url), location.href);
            return parsed.protocol === 'https:' && parsed.hostname.toLowerCase() === 'graph.microsoft.com';
        } catch (_) {
            return false;
        }
    }

    function base64UrlDecode(value) {
        try {
            let input = value.replace(/-/g, '+').replace(/_/g, '/');
            while (input.length % 4) input += '=';
            const binary = atob(input);
            const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
            return new TextDecoder().decode(bytes);
        } catch (_) {
            return null;
        }
    }

    function decodeJwtPayload(token) {
        const parts = String(token || '').split('.');
        if (parts.length !== 3) return null;
        const decoded = base64UrlDecode(parts[1]);
        if (!decoded) return null;
        try {
            return JSON.parse(decoded);
        } catch (_) {
            return null;
        }
    }

    function tokenLooksLikeGraphToken(token, sourceUrl) {
        if (!token || token.length < 100) return false;
        if (sourceUrl && isGraphUrl(sourceUrl)) return true;

        const payload = decodeJwtPayload(token);
        if (!payload) return false;
        const aud = Array.isArray(payload.aud) ? payload.aud.join(' ') : String(payload.aud || '');
        return aud.toLowerCase().includes('graph.microsoft.com') || aud.toLowerCase() === GRAPH_RESOURCE_APP_ID;
    }

    function getTokenScopes(token) {
        const payload = decodeJwtPayload(token);
        if (!payload) return [];

        const values = [];
        if (typeof payload.scp === 'string') values.push(...payload.scp.split(/\s+/));
        if (Array.isArray(payload.roles)) values.push(...payload.roles);
        return [...new Set(values.filter(Boolean))];
    }

    function getTokenExpiry(token) {
        const payload = decodeJwtPayload(token);
        return payload && Number.isFinite(Number(payload.exp)) ? Number(payload.exp) : null;
    }

    function tokenIsExpired(entry) {
        return entry.exp !== null && entry.exp <= Math.floor(Date.now() / 1000) + 30;
    }

    function bearerFromHeader(value) {
        if (typeof value !== 'string') return null;
        const match = /^Bearer\s+(.+)$/i.exec(value.trim());
        return match ? match[1].trim() : null;
    }

    function readHeader(headers, name) {
        if (!headers) return null;
        const wanted = name.toLowerCase();

        try {
            if (typeof headers.get === 'function') {
                return headers.get(name) || headers.get(wanted);
            }
        } catch (_) {
            // continue with other representations
        }

        if (Array.isArray(headers)) {
            const pair = headers.find(item => Array.isArray(item) && String(item[0]).toLowerCase() === wanted);
            return pair ? pair[1] : null;
        }

        if (typeof headers === 'object') {
            for (const key of Object.keys(headers)) {
                if (key.toLowerCase() === wanted) return headers[key];
            }
        }

        return null;
    }

    function notifyTopAboutToken(token) {
        if (!isReactBladeHost() || window.top === window.self) return;
        try {
            window.parent.postMessage({ type: MSG_TOKEN, token }, INTUNE_ORIGIN);
        } catch (_) {
            // best effort only
        }
    }

    function rememberToken(token, sourceUrl = GRAPH_ORIGIN, relay = true) {
        token = String(token || '').trim();
        if (!tokenLooksLikeGraphToken(token, sourceUrl)) return false;

        const existing = tokenStore.find(item => item.token === token);
        if (existing) {
            existing.lastSeen = Date.now();
            return true;
        }

        const entry = {
            token,
            scopes: getTokenScopes(token),
            exp: getTokenExpiry(token),
            lastSeen: Date.now()
        };

        tokenStore.push(entry);
        tokenStore.sort((a, b) => b.lastSeen - a.lastSeen);
        while (tokenStore.length > 40) tokenStore.pop();

        log('Microsoft Graph token detected.', entry.scopes.length ? `Scopes: ${entry.scopes.join(', ')}` : 'Scopes unavailable');
        if (relay) notifyTopAboutToken(token);
        return true;
    }

    function rememberMsalAccessTokenCandidate(token, target = '', relay = true) {
        token = String(token || '').trim();
        if (!token || token.length < 100) return false;

        const existing = tokenStore.find(item => item.token === token);
        if (existing) {
            existing.lastSeen = Date.now();
            if (target) {
                const targetScopes = String(target).split(/\s+/).filter(Boolean);
                existing.scopes = [...new Set([...existing.scopes, ...targetScopes])];
            }
            return true;
        }

        const targetScopes = String(target || '').split(/\s+/).filter(Boolean);
        const jwtScopes = getTokenScopes(token);
        const entry = {
            token,
            scopes: [...new Set([...jwtScopes, ...targetScopes])],
            exp: getTokenExpiry(token),
            lastSeen: Date.now()
        };

        tokenStore.push(entry);
        tokenStore.sort((a, b) => b.lastSeen - a.lastSeen);
        while (tokenStore.length > 40) tokenStore.pop();

        log('MSAL access-token candidate detected.', entry.scopes.length ? `Target/scopes: ${entry.scopes.join(', ')}` : 'Target unavailable');
        if (relay) notifyTopAboutToken(token);
        return true;
    }

    function notifyTopAboutDeviceId(deviceId) {
        if (!isReactBladeHost() || window.top === window.self) return;
        try {
            window.parent.postMessage({ type: MSG_DEVICE_ID, deviceId }, INTUNE_ORIGIN);
        } catch (_) {
            // best effort only
        }
    }

    function captureDeviceIdFromUrl(url, relay = true) {
        if (!url) return null;

        let text = String(url);
        try { text = decodeURIComponent(text); } catch (_) { /* keep raw URL */ }

        // DeviceGroupMembership.ReactView currently loads its membership list
        // with a query containing: filter=deviceId eq '<Entra deviceId>'.
        const match = /(?:\$?filter=)?deviceId\s+eq\s+['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]/i.exec(text);
        if (!match || !GUID_RE.test(match[1])) return null;

        const deviceId = match[1].toLowerCase();
        if (observedEntraDeviceId !== deviceId) {
            observedEntraDeviceId = deviceId;
            log('Entra deviceId detected in group search request:', deviceId);
            if (relay) notifyTopAboutDeviceId(deviceId);
        }
        return deviceId;
    }

    function captureAuthorization(url, authHeader) {
        if (!isGraphUrl(url)) return;
        const token = bearerFromHeader(authHeader);
        if (token) rememberToken(token, url);
    }

    function installTokenHooks() {
        if (pageWindow.__TM_DGM_TOKEN_HOOK_V1__) return;
        pageWindow.__TM_DGM_TOKEN_HOOK_V1__ = true;

        try {
            const originalFetch = pageWindow.fetch;
            if (typeof originalFetch === 'function') {
                pageWindow.fetch = function (input, init) {
                    try {
                        const url = typeof input === 'string' || input instanceof URL ? String(input) : input && input.url;
                        captureDeviceIdFromUrl(url);
                        const auth = readHeader(init && init.headers, 'Authorization') || readHeader(input && input.headers, 'Authorization');
                        captureAuthorization(url, auth);
                    } catch (_) {
                        // never break the portal request
                    }
                    return originalFetch.apply(this, arguments);
                };
            }
        } catch (error) {
            warn('Could not install the fetch hook:', error);
        }

        try {
            const XHR = pageWindow.XMLHttpRequest;
            if (XHR && XHR.prototype) {
                const originalOpen = XHR.prototype.open;
                const originalSetRequestHeader = XHR.prototype.setRequestHeader;

                XHR.prototype.open = function (method, url) {
                    try {
                        this.__tmDgmUrl = url;
                        captureDeviceIdFromUrl(url);
                    } catch (_) {
                        // ignore
                    }
                    return originalOpen.apply(this, arguments);
                };

                XHR.prototype.setRequestHeader = function (name, value) {
                    try {
                        if (String(name).toLowerCase() === 'authorization') {
                            captureAuthorization(this.__tmDgmUrl, value);
                        }
                    } catch (_) {
                        // never break the portal request
                    }
                    return originalSetRequestHeader.apply(this, arguments);
                };
            }
        } catch (error) {
            warn('Could not install the XMLHttpRequest hook:', error);
        }
    }

    function parseJsonObject(value) {
        if (!value || typeof value !== 'string') return null;
        try {
            let parsed = JSON.parse(value);
            // Some caches contain a JSON string that itself contains JSON.
            if (typeof parsed === 'string' && parsed.length > 1 && (parsed.startsWith('{') || parsed.startsWith('['))) {
                parsed = JSON.parse(parsed);
            }
            return parsed && typeof parsed === 'object' ? parsed : null;
        } catch (_) {
            return null;
        }
    }

    function scanMsalSessionStorageAccessTokens(force = false) {
        if (!force && Date.now() - lastStorageScan < 5000) return;

        let storage;
        try { storage = pageWindow.sessionStorage; } catch (_) { return; }
        if (!storage) return;

        const entries = [];
        let length = 0;
        try { length = storage.length; } catch (_) { return; }

        for (let i = 0; i < length; i++) {
            try {
                const key = storage.key(i) || '';
                const raw = storage.getItem(key) || '';
                if (!raw || raw.length > 2_000_000) continue;
                const object = parseJsonObject(raw);
                if (object) entries.push({ key, object });
            } catch (_) {
                // skip malformed/inaccessible cache items
            }
        }

        // Same approach as the earlier Intune userscript: identify MSAL account
        // records first, then use AccessToken credentials for the same homeAccountId.
        const homeAccountIds = new Set();
        for (const { object } of entries) {
            if (object && object.username && object.homeAccountId) {
                homeAccountIds.add(String(object.homeAccountId));
            }
        }

        let found = 0;
        for (const { key, object } of entries) {
            if (!object || object.credentialType !== 'AccessToken' || !object.secret) continue;
            if (homeAccountIds.size > 0 && object.homeAccountId && !homeAccountIds.has(String(object.homeAccountId))) continue;

            const target = object.target || object.scopes || key;
            if (rememberMsalAccessTokenCandidate(object.secret, target)) found++;
        }

        if (found > 0) {
            log(`${found} MSAL AccessToken-Kandidat(en) aus sessionStorage übernommen.`);
        }
    }

    function scanStorageForGraphTokens(force = false) {
        if (!force && Date.now() - lastStorageScan < 5000) return;
        lastStorageScan = Date.now();

        const storages = [];
        try { storages.push(pageWindow.sessionStorage); } catch (_) { /* ignore */ }
        try { storages.push(pageWindow.localStorage); } catch (_) { /* ignore */ }

        const tokenPattern = /[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]*){2,4}/g;

        for (const storage of storages) {
            if (!storage) continue;
            let length = 0;
            try { length = storage.length; } catch (_) { continue; }

            for (let i = 0; i < length; i++) {
                let key;
                let value;
                try {
                    key = storage.key(i) || '';
                    value = storage.getItem(key) || '';
                } catch (_) {
                    continue;
                }

                if (!value || value.length > 2_000_000) continue;
                const context = `${key} ${value.slice(0, 4096)}`;
                const graphContext = /graph\.microsoft\.com|00000003-0000-0000-c000-000000000000/i.test(context);
                if (!graphContext) continue;

                const candidates = value.match(tokenPattern) || [];
                for (const candidate of candidates) {
                    // Storage context identifies this cache entry as Microsoft Graph.
                    rememberToken(candidate, GRAPH_ORIGIN);
                }
            }
        }
    }

    function exportTokenStrings() {
        return tokenStore
            .filter(entry => !tokenIsExpired(entry))
            .sort((a, b) => b.lastSeen - a.lastSeen)
            .slice(0, 30)
            .map(entry => entry.token);
    }

    function rankTokens(preferredScopes = []) {
        const preferred = new Set(preferredScopes.map(value => value.toLowerCase()));

        return tokenStore
            .filter(entry => !tokenIsExpired(entry))
            .map(entry => {
                const lowerScopes = new Set(entry.scopes.map(value => value.toLowerCase()));
                let score = 0;
                for (const scope of preferred) {
                    if (lowerScopes.has(scope)) score += 1000;
                }
                if (entry.scopes.length === 0) score += 100; // opaque/JWE token: still try it
                score += Math.min(99, Math.floor((entry.lastSeen % 100000) / 1000));
                return { entry, score };
            })
            .sort((a, b) => b.score - a.score || b.entry.lastSeen - a.entry.lastSeen)
            .map(item => item.entry);
    }

    installTokenHooks();
    scanMsalSessionStorageAccessTokens(true);
    scanStorageForGraphTokens(true);

    // ---------------------------------------------------------------------
    // Top-level Intune portal: provide managedDeviceId + in-memory tokens.
    // ---------------------------------------------------------------------

    function extractManagedDeviceId() {
        const match = MANAGED_DEVICE_RE.exec(location.hash || '');
        return match ? match[1] : null;
    }

    function findDirectIframeByWindow(sourceWindow) {
        try {
            return [...document.querySelectorAll('iframe')].find(frame => frame.contentWindow === sourceWindow) || null;
        } catch (_) {
            return null;
        }
    }

    function installTopPortalBridge() {
        window.addEventListener('message', event => {
            if (!isAllowedReactBladeOrigin(event.origin)) return;
            if (!event.data || typeof event.data !== 'object') return;

            const frame = findDirectIframeByWindow(event.source);
            if (!frame) return;

            if (event.data.type === MSG_TOKEN) {
                rememberToken(event.data.token, GRAPH_ORIGIN, false);
                return;
            }

            if (event.data.type === MSG_DEVICE_ID) {
                const deviceId = String(event.data.deviceId || '').toLowerCase();
                if (GUID_RE.test(deviceId)) observedEntraDeviceId = deviceId;
                return;
            }

            if (event.data.type !== MSG_REQUEST_CONTEXT) return;

            // Do not depend on iframe.name/window.name here. Azure Portal can
            // recreate ReactBlade browsing contexts and the window name is not
            // reliable in every portal build. The source is already restricted
            // to a direct child frame on an allowed ReactBlade origin.
            scanMsalSessionStorageAccessTokens();
            scanStorageForGraphTokens();
            const managedDeviceId = extractManagedDeviceId();
            try {
                const frameName = frame.getAttribute('name') || '';
                const frameSrc = frame.getAttribute('src') || frame.src || '';
                event.source.postMessage({
                    type: MSG_CONTEXT,
                    managedDeviceId,
                    entraDeviceId: observedEntraDeviceId,
                    tokens: exportTokenStrings(),
                    frameName,
                    frameSrc,
                    isDeviceGroupMembershipFrame: frameName === 'DeviceGroupMembership.ReactView'
                }, event.origin);
            } catch (error) {
                warn('Could not send context to DeviceGroupMembership.ReactView:', error);
            }
        });

        log('Intune-Bridge aktiv.');
    }

    if (location.hostname.toLowerCase() === 'intune.microsoft.com' && window.top === window.self) {
        installTopPortalBridge();
        return;
    }

    // All ReactBlade frames keep the token hook active. Do not depend on
    // window.name to decide whether this is DeviceGroupMembership.ReactView.
    // Instead, the UI is activated only after the characteristic group grid
    // DOM is detected. This survives Azure Portal recreating/renaming frames.
    if (!isReactBladeHost()) return;

    log('ReactBlade frame detected:', location.hostname, 'window.name=', (() => {
        try { return window.name || '(empty)'; } catch (_) { return '(unavailable)'; }
    })());

    // ---------------------------------------------------------------------
    // DeviceGroupMembership.ReactView UI
    // ---------------------------------------------------------------------

    const selectedGroups = new Map();
    const context = { managedDeviceId: null, entraDeviceId: null, frameName: '', frameSrc: '', isDeviceGroupMembershipFrame: false };
    let frameIdentityLogged = false;
    let busy = false;
    let observer = null;
    let renderQueued = false;
    let contextTimer = null;
    const syntheticRowCells = new WeakMap();

    // Add-groups popover state. Selection intentionally survives new searches
    // while the popover is open, so several independently found groups can be
    // collected and committed in one operation.
    const pendingAddGroups = new Map();
    let addBusy = false;
    let addSearchTimer = null;
    let addSearchSequence = 0;
    let addSearchResults = [];
    let lastAddSearchQuery = '';

    function requestContext() {
        try {
            window.parent.postMessage({ type: MSG_REQUEST_CONTEXT }, INTUNE_ORIGIN);
        } catch (_) {
            // handled later when the action is invoked
        }
    }

    window.addEventListener('message', event => {
        if (event.origin !== INTUNE_ORIGIN) return;
        if (!event.data || event.data.type !== MSG_CONTEXT) return;

        if (event.data.managedDeviceId && GUID_RE.test(event.data.managedDeviceId)) {
            context.managedDeviceId = event.data.managedDeviceId;
        }
        if (event.data.entraDeviceId && GUID_RE.test(event.data.entraDeviceId)) {
            context.entraDeviceId = String(event.data.entraDeviceId).toLowerCase();
            observedEntraDeviceId = context.entraDeviceId;
        }

        context.frameName = String(event.data.frameName || '');
        context.frameSrc = String(event.data.frameSrc || '');
        context.isDeviceGroupMembershipFrame = event.data.isDeviceGroupMembershipFrame === true ||
            context.frameName === 'DeviceGroupMembership.ReactView';

        if (!frameIdentityLogged) {
            frameIdentityLogged = true;
            log('Parent frame detected:', {
                frameName: context.frameName || '(empty)',
                isDeviceGroupMembershipFrame: context.isDeviceGroupMembershipFrame,
                frameSrc: context.frameSrc || '(empty)'
            });
        }

        if (Array.isArray(event.data.tokens)) {
            for (const token of event.data.tokens) {
                rememberToken(token, GRAPH_ORIGIN, false);
            }
        }

        queueRender();
    });

    function addStyle() {
        if (document.getElementById('tm-dgm-style')) return;
        const style = document.createElement('style');
        style.id = 'tm-dgm-style';
        style.textContent = `
            .tm-dgm-checkbox-wrap {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                flex: 0 0 28px;
                width: 28px;
                min-width: 28px;
                height: 100%;
                box-sizing: border-box;
            }
            .tm-dgm-checkbox {
                width: 16px;
                height: 16px;
                margin: 0;
                cursor: pointer;
                accent-color: var(--colorControlBackgroundBrand, #0078d4);
            }
            .tm-dgm-checkbox:disabled {
                cursor: not-allowed;
                opacity: 0.45;
            }
            /* Mirror the native Intune/Fluent command state. The portal's own
             * Remove Members button uses the class "is-disabled" together with
             * aria-disabled instead of the HTML disabled attribute. */
            #tm-dgm-remove-button.is-disabled {
                cursor: default !important;
                pointer-events: none !important;
                color: #a19f9d !important;
            }
            #tm-dgm-remove-button.is-disabled .ms-Button-label,
            #tm-dgm-remove-button.is-disabled .ms-Button-icon,
            #tm-dgm-remove-button.is-disabled .ms-Icon {
                color: #a19f9d !important;
            }
            #tm-dgm-remove-button:not(.is-disabled) {
                opacity: 1 !important;
                cursor: pointer !important;
                pointer-events: auto !important;
                color: #ffffff !important;
            }
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-label,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-icon,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Icon {
                color: var(--colorButtonToolbardForeground, #ffffff) !important;
                opacity: 1 !important;
            }

            /* Native Intune command-bar foreground/cursor behavior. */
            #tm-dgm-add-button,
            #tm-dgm-add-button .ms-Button-flexContainer,
            #tm-dgm-add-button .ms-Button-textContainer,
            #tm-dgm-add-button .ms-Button-label,
            #tm-dgm-add-button .ms-Button-icon,
            #tm-dgm-add-button .ms-Icon,
            #tm-dgm-remove-button:not(.is-disabled),
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-flexContainer,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-textContainer,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-label,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Button-icon,
            #tm-dgm-remove-button:not(.is-disabled) .ms-Icon {
                color: var(--colorButtonToolbardForeground, #ffffff) !important;
                cursor: pointer !important;
            }
            #tm-dgm-add-button {
                opacity: 1 !important;
                pointer-events: auto !important;
            }
            #tm-dgm-add-toolbar-item {
                cursor: pointer !important;
            }
            #tm-dgm-toolbar-item:has(#tm-dgm-remove-button:not(.is-disabled)) {
                cursor: pointer !important;
            }
            #tm-dgm-remove-button.is-disabled,
            #tm-dgm-remove-button.is-disabled * {
                cursor: default !important;
            }
            #tm-dgm-add-popover-overlay {
                position: fixed;
                inset: 0;
                z-index: 299998;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 24px;
                box-sizing: border-box;
                background: rgba(0, 0, 0, 0.30);
                font-family: "Segoe UI", sans-serif;
            }
            #tm-dgm-add-popover {
                width: min(1120px, calc(100vw - 48px));
                height: min(720px, calc(100vh - 64px));
                min-height: 520px;
                display: flex;
                flex-direction: column;
                overflow: hidden;
                background: var(--colorContainerBackgroundPrimary, #ffffff);
                color: var(--colorTextPrimary, #323130);
                border: 1px solid var(--colorContainerBorderSecondary, #d2d0ce);
                border-radius: 2px;
                box-shadow: var(--shadowLevel4, 0 25.6px 57.6px rgba(0,0,0,.32));
            }
            .tm-dgm-picker-titlebar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex: 0 0 52px;
                min-height: 52px;
                padding: 0 16px 0 20px;
                box-sizing: border-box;
                border-bottom: 1px solid var(--colorContainerBorderPrimary, #edebe9);
            }
            .tm-dgm-picker-title {
                margin: 0;
                font-size: 20px;
                line-height: 28px;
                font-weight: 600;
                color: var(--colorTextPrimary, #323130);
            }
            .tm-dgm-picker-close {
                width: 32px;
                height: 32px;
                padding: 0;
                border: 0;
                background: transparent;
                color: var(--colorButtonToolbardForeground, var(--colorTextPrimary, #323130));
                cursor: pointer;
            }
            .tm-dgm-picker-close:hover {
                background: var(--colorControlBackgroundHover, #f3f2f1);
            }
            .tm-dgm-picker-close i {
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 14px;
            }
            .tm-dgm-picker-main {
                display: grid;
                grid-template-columns: minmax(0, 2fr) minmax(280px, .8fr);
                flex: 1 1 auto;
                min-height: 0;
                overflow: hidden;
            }
            .tm-dgm-picker-left {
                display: flex;
                flex-direction: column;
                min-width: 0;
                min-height: 0;
                padding: 16px 18px 0 20px;
                box-sizing: border-box;
            }
            .tm-dgm-picker-message {
                display: flex;
                align-items: flex-start;
                gap: 10px;
                flex: 0 0 auto;
                margin-bottom: 12px;
                padding: 8px 10px;
                border: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                background: var(--colorContainerBackgroundSecondary, #f3f2f1);
                font-size: 13px;
                line-height: 18px;
            }
            .tm-dgm-picker-message i {
                margin-top: 1px;
                font-family: FabricMDL2Icons;
                font-style: normal;
                color: var(--colorIconInfo, #0078d4);
            }
            .tm-dgm-search-label {
                display: block;
                margin-bottom: 5px;
                font-size: 13px;
                line-height: 18px;
            }
            .tm-dgm-native-searchbox {
                position: relative;
                display: flex;
                align-items: center;
                flex: 0 0 32px;
                height: 32px;
                box-sizing: border-box;
                border: 1px solid var(--colorControlBorder, #8a8886);
                background: var(--colorControlBackground, #ffffff);
                color: var(--colorTextPrimary, #323130);
            }
            .tm-dgm-native-searchbox:focus-within {
                border-color: var(--colorControlBorderFocus, #0078d4);
                box-shadow: inset 0 0 0 1px var(--colorControlBorderFocus, #0078d4);
            }
            .tm-dgm-native-search-icon {
                flex: 0 0 32px;
                width: 32px;
                text-align: center;
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 14px;
                color: var(--colorIconSecondary, #605e5c);
            }
            #tm-dgm-group-search {
                flex: 1 1 auto;
                min-width: 0;
                height: 30px;
                padding: 0 4px 0 0;
                border: 0;
                outline: 0;
                background: transparent;
                color: var(--colorTextPrimary, #323130);
                font: inherit;
            }
            .tm-dgm-search-clear {
                flex: 0 0 32px;
                width: 32px;
                height: 30px;
                padding: 0;
                border: 0;
                background: transparent;
                color: var(--colorIconPrimary, #323130);
                cursor: pointer;
            }
            .tm-dgm-search-clear:hover {
                background: var(--colorControlBackgroundHover, #f3f2f1);
            }
            .tm-dgm-search-clear i {
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 12px;
            }
            .tm-dgm-search-status {
                flex: 0 0 auto;
                min-height: 18px;
                padding: 7px 5px 5px;
                font-size: 13px;
                line-height: 18px;
                color: var(--colorTextSecondary, #605e5c);
            }
            .tm-dgm-picker-pivot {
                display: flex;
                flex: 0 0 36px;
                min-height: 36px;
                border-bottom: 1px solid var(--colorContainerBorderPrimary, #edebe9);
            }
            .tm-dgm-picker-pivot-button {
                position: relative;
                min-width: 68px;
                padding: 0 8px;
                border: 0;
                background: transparent;
                color: var(--colorTextPrimary, #323130);
                font: inherit;
                font-weight: 600;
            }
            .tm-dgm-picker-pivot-button::after {
                content: "";
                position: absolute;
                left: 8px;
                right: 8px;
                bottom: 0;
                height: 2px;
                background: var(--colorControlBackgroundBrand, #0078d4);
            }
            .tm-dgm-results-shell {
                display: flex;
                flex-direction: column;
                flex: 1 1 auto;
                min-height: 0;
            }
            .tm-dgm-results-header {
                display: grid;
                grid-template-columns: 42px minmax(220px, 1fr) 110px minmax(160px, .8fr);
                flex: 0 0 42px;
                align-items: center;
                min-height: 42px;
                border-bottom: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                font-size: 12px;
                font-weight: 600;
                color: var(--colorTextSecondary, #605e5c);
            }
            .tm-dgm-results-header > div {
                padding: 0 10px;
                box-sizing: border-box;
            }
            .tm-dgm-results {
                flex: 1 1 auto;
                min-height: 0;
                overflow: auto;
            }
            .tm-dgm-picker-row {
                display: grid;
                grid-template-columns: 42px minmax(220px, 1fr) 110px minmax(160px, .8fr);
                align-items: stretch;
                min-height: 44px;
                border-bottom: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                cursor: pointer;
                user-select: none;
            }
            .tm-dgm-picker-row:hover:not(.is-disabled) {
                background: var(--todoFocusRowHover, var(--colorControlBackgroundHover, #f3f2f1));
            }
            .tm-dgm-picker-row.is-selected {
                background: var(--colorControlBackgroundSelected, rgba(0,120,212,.12));
            }
            .tm-dgm-picker-row.is-disabled {
                cursor: default;
                color: var(--colorTextDisabled, #a19f9d);
            }
            .tm-dgm-picker-cell {
                display: flex;
                align-items: center;
                min-width: 0;
                padding: 6px 10px;
                box-sizing: border-box;
                font-size: 13px;
                line-height: 18px;
            }
            .tm-dgm-picker-cell-name {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .tm-dgm-picker-cell-details {
                color: var(--colorTextSecondary, #605e5c);
                font-size: 12px;
            }
            .tm-dgm-picker-row.is-disabled .tm-dgm-picker-cell-details {
                color: var(--colorTextDisabled, #a19f9d);
            }
            .tm-dgm-native-check-cell {
                justify-content: center;
                padding: 0;
            }
            .tm-dgm-native-check {
                position: relative;
                width: 18px;
                height: 18px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--colorIconSecondary, #605e5c);
            }
            .tm-dgm-native-check i {
                position: absolute;
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 16px;
                line-height: 18px;
            }
            .tm-dgm-native-check .tm-dgm-check-circle { opacity: 1; }
            .tm-dgm-native-check .tm-dgm-check-mark {
                opacity: 0;
                color: var(--colorControlBackgroundBrand, #0078d4);
            }
            .tm-dgm-picker-row.is-selected .tm-dgm-native-check .tm-dgm-check-circle { opacity: 0; }
            .tm-dgm-picker-row.is-selected .tm-dgm-native-check .tm-dgm-check-mark { opacity: 1; }
            .tm-dgm-picker-row.is-disabled .tm-dgm-native-check { opacity: .45; }
            .tm-dgm-empty {
                padding: 28px 16px;
                text-align: center;
                color: var(--colorTextSecondary, #605e5c);
                font-size: 13px;
            }
            .tm-dgm-picker-cart {
                display: flex;
                flex-direction: column;
                min-width: 0;
                min-height: 0;
                border-left: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                background: var(--colorContainerBackgroundPrimary, #ffffff);
            }
            .tm-dgm-selected-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex: 0 0 48px;
                min-height: 48px;
                padding: 0 12px 0 16px;
                border-bottom: 1px solid var(--colorContainerBorderPrimary, #edebe9);
            }
            .tm-dgm-selected-title {
                margin: 0;
                font-size: 14px;
                line-height: 20px;
                font-weight: 600;
                color: var(--colorTextPrimary, #323130);
            }
            .tm-dgm-reset-button {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                height: 32px;
                padding: 0 8px;
                border: 0;
                background: transparent;
                color: var(--colorButtonToolbardForeground, var(--colorTextPrimary, #323130));
                font: inherit;
                cursor: pointer;
            }
            .tm-dgm-reset-button:hover:not(:disabled) {
                background: var(--colorControlBackgroundHover, #f3f2f1);
            }
            .tm-dgm-reset-button:disabled {
                color: var(--colorTextDisabled, #a19f9d);
                cursor: default;
            }
            .tm-dgm-reset-button i {
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 14px;
            }
            .tm-dgm-selected-list {
                flex: 1 1 auto;
                min-height: 0;
                overflow: auto;
                padding: 8px 0;
            }
            .tm-dgm-selected-empty {
                padding: 8px 16px;
                color: var(--colorTextSecondary, #605e5c);
                font-size: 13px;
            }
            .tm-dgm-selected-row {
                display: grid;
                grid-template-columns: 34px minmax(0, 1fr) 32px;
                align-items: center;
                min-height: 46px;
                padding: 2px 8px 2px 12px;
                box-sizing: border-box;
            }
            .tm-dgm-selected-row:hover {
                background: var(--colorControlBackgroundHover, #f3f2f1);
            }
            .tm-dgm-selected-icon {
                width: 28px;
                height: 28px;
                display: flex;
                align-items: center;
                justify-content: center;
                box-sizing: border-box;
                border-top-left-radius: 7px;
                border-bottom-right-radius: 7px;
                background: var(--colorControlBackgroundBrand, #0078d4);
                color: #ffffff;
                font-size: 11px;
                font-weight: 600;
            }
            .tm-dgm-selected-name {
                min-width: 0;
                padding-left: 8px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                font-size: 13px;
            }
            .tm-dgm-selected-remove {
                width: 28px;
                height: 28px;
                padding: 0;
                border: 0;
                background: transparent;
                color: var(--colorIconPrimary, #323130);
                cursor: pointer;
            }
            .tm-dgm-selected-remove:hover {
                background: var(--colorControlBackgroundHover, #f3f2f1);
            }
            .tm-dgm-selected-remove i {
                font-family: FabricMDL2Icons;
                font-style: normal;
                font-size: 12px;
            }
            .tm-dgm-add-footer {
                display: flex;
                align-items: center;
                justify-content: flex-end;
                flex: 0 0 56px;
                min-height: 56px;
                padding: 0 20px;
                box-sizing: border-box;
                border-top: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                background: var(--colorContainerBackgroundPrimary, #ffffff);
            }
            #tm-dgm-add-apply {
                min-width: 88px;
                height: 32px;
                padding: 0 16px;
                border: 1px solid var(--colorButtonBackgroundPrimary, #0078d4);
                border-radius: 2px;
                background: var(--colorButtonBackgroundPrimary, #0078d4);
                color: var(--colorButtonForegroundPrimary, #ffffff);
                font: 600 13px "Segoe UI", sans-serif;
                cursor: pointer;
            }
            #tm-dgm-add-apply:hover:not(:disabled) {
                background: var(--colorButtonBackgroundPrimaryHover, #106ebe);
                border-color: var(--colorButtonBackgroundPrimaryHover, #106ebe);
            }
            #tm-dgm-add-apply:disabled {
                background: var(--colorButtonBackgroundDisabled, #f3f2f1);
                border-color: var(--colorControlBorderDisabled, #d2d0ce);
                color: var(--colorButtonForegroundDisabled, #a19f9d);
                cursor: default;
            }
            @media (max-width: 850px) {
                #tm-dgm-add-popover {
                    width: calc(100vw - 24px);
                    height: calc(100vh - 24px);
                }
                .tm-dgm-picker-main {
                    grid-template-columns: 1fr;
                    grid-template-rows: minmax(0, 1fr) 210px;
                }
                .tm-dgm-picker-cart {
                    border-left: 0;
                    border-top: 1px solid var(--colorContainerBorderPrimary, #edebe9);
                }
            }
            #tm-dgm-toast-container {
                position: fixed;
                top: 12px;
                right: 24px;
                z-index: 300000;
                display: flex;
                flex-direction: column;
                gap: 8px;
                pointer-events: none;
            }
            .tm-dgm-toast {
                min-width: 260px;
                max-width: 520px;
                padding: 10px 14px;
                border: 1px solid var(--colorControlBorderSecondary, #8a8886);
                background: var(--colorContainerBackgroudFloating, #252423);
                color: var(--colorTextPrimary, #faf9f8);
                box-shadow: 0 3.2px 7.2px rgba(0,0,0,.25);
                font-family: "Segoe UI", sans-serif;
                font-size: 13px;
                line-height: 18px;
                white-space: pre-wrap;
            }
            .tm-dgm-toast-error {
                border-color: var(--colorControlBorderError, #d13438);
            }
        `;
        (document.head || document.documentElement).appendChild(style);
    }

    function showToast(message, isError = false, timeout = 5000) {
        let container = document.getElementById('tm-dgm-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'tm-dgm-toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `tm-dgm-toast${isError ? ' tm-dgm-toast-error' : ''}`;
        toast.textContent = message;
        container.appendChild(toast);
        window.setTimeout(() => toast.remove(), timeout);
    }

    function getCell(row, key) {
        // Newer ReactBlade builds can render the four logical columns in
        // separate DOM branches. In that case there is no common per-row
        // ancestor. syntheticRowCells maps the groupName cell to the matching
        // cells by their rendered list index.
        const synthetic = row && syntheticRowCells.get(row);
        if (synthetic && synthetic[key]) return synthetic[key];

        // data-automation-key is considerably more stable than generated
        // Fluent UI class names.
        return row && typeof row.querySelector === 'function'
            ? row.querySelector(`[data-automation-key="${key}"]`)
            : null;
    }

    function findGroupRows() {
        const REQUIRED_KEYS = [
            'groupName',
            'objectID',
            'localizedMembershipTypeString',
            'localizedMembershipSourceString'
        ];

        const cellsByKey = Object.fromEntries(REQUIRED_KEYS.map(key => [
            key,
            [...document.querySelectorAll(`[data-automation-key="${key}"]`)]
        ]));

        const counts = REQUIRED_KEYS.map(key => cellsByKey[key].length);
        const minCount = Math.min(...counts);
        const maxCount = Math.max(...counts);

        // This is the normal path for the current DeviceGroupMembership.ReactView:
        // Intune loads the membership list asynchronously (filter=deviceId eq ...),
        // then renders every logical column with the same number/order of items.
        // Pairing by index is therefore independent of the changing Fluent UI
        // wrapper hierarchy and also survives virtualized/search reloads.
        if (minCount > 0 && minCount === maxCount) {
            const rows = [];
            for (let index = 0; index < minCount; index++) {
                const rowKey = cellsByKey.groupName[index];
                syntheticRowCells.set(rowKey, {
                    groupName: cellsByKey.groupName[index],
                    objectID: cellsByKey.objectID[index],
                    localizedMembershipTypeString: cellsByKey.localizedMembershipTypeString[index],
                    localizedMembershipSourceString: cellsByKey.localizedMembershipSourceString[index]
                });
                rows.push(rowKey);
            }
            return rows;
        }

        // Fallback for older builds where all cells still share a real row
        // container. This is intentionally secondary because current Intune
        // ReactBlade markup can split the logical row across DOM branches.
        const rows = new Set();

        function containsAllRequiredKeys(node) {
            if (!node || node.nodeType !== Node.ELEMENT_NODE) return false;
            return REQUIRED_KEYS.every(key => node.querySelector(`[data-automation-key="${key}"]`));
        }

        function findTightRowContainer(cell) {
            const semantic = cell.closest(
                '[role="row"], [data-automationid="DetailsRow"], [data-item-index], [data-selection-index]'
            );
            if (semantic && containsAllRequiredKeys(semantic)) return semantic;

            let node = cell.parentElement;
            for (let depth = 0; node && depth < 18; depth++, node = node.parentElement) {
                if (!containsAllRequiredKeys(node)) continue;
                if (node.querySelectorAll('[data-automation-key="groupName"]').length === 1 &&
                    node.querySelectorAll('[data-automation-key="objectID"]').length === 1) {
                    return node;
                }
            }
            return null;
        }

        cellsByKey.groupName.forEach(cell => {
            const row = findTightRowContainer(cell);
            if (row) rows.add(row);
        });

        if (rows.size === 0 && minCount > 0) {
            log('Group cells are not fully synchronized yet:', {
                groupName: cellsByKey.groupName.length,
                objectID: cellsByKey.objectID.length,
                membershipType: cellsByKey.localizedMembershipTypeString.length,
                membershipSource: cellsByKey.localizedMembershipSourceString.length
            });
        }

        return [...rows];
    }

    function isGroupMembershipDomPresent() {
        return findGroupRows().some(row => getMembershipState(row));
    }

    function cleanText(element) {
        return String(element && element.textContent || '').replace(/\s+/g, ' ').trim();
    }

    function extractGuidFromElement(element) {
        if (!element) return null;

        const candidates = [
            element.textContent,
            element.getAttribute && element.getAttribute('title'),
            element.getAttribute && element.getAttribute('aria-label'),
            element.getAttribute && element.getAttribute('data-id'),
            element.getAttribute && element.getAttribute('data-object-id')
        ];

        try {
            element.querySelectorAll('a[href], [title], [aria-label], [data-id], [data-object-id]').forEach(child => {
                candidates.push(
                    child.textContent,
                    child.getAttribute('href'),
                    child.getAttribute('title'),
                    child.getAttribute('aria-label'),
                    child.getAttribute('data-id'),
                    child.getAttribute('data-object-id')
                );
            });
        } catch (_) {
            // best effort only
        }

        const guidAnywhere = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
        for (const value of candidates) {
            const match = guidAnywhere.exec(String(value || ''));
            if (match) return match[0];
        }
        return null;
    }

    function hasGroupMembershipColumns() {
        return !!(
            document.querySelector('[data-automation-key="groupName"]') &&
            document.querySelector('[data-automation-key="objectID"]') &&
            document.querySelector('[data-automation-key="localizedMembershipTypeString"]') &&
            document.querySelector('[data-automation-key="localizedMembershipSourceString"]')
        );
    }

    function getGroupName(groupNameCell) {
        const link = groupNameCell && groupNameCell.querySelector('a');
        return cleanText(link || groupNameCell) || '(unnamed group)';
    }

    function getMembershipState(row) {
        const groupNameCell = getCell(row, 'groupName');
        const idCell = getCell(row, 'objectID');
        const typeCell = getCell(row, 'localizedMembershipTypeString');
        const sourceCell = getCell(row, 'localizedMembershipSourceString');

        if (!groupNameCell || !idCell || !typeCell || !sourceCell) return null;

        const groupId = extractGuidFromElement(idCell);
        if (!groupId || !GUID_RE.test(groupId)) return null;

        const name = getGroupName(groupNameCell);
        const membershipType = cleanText(typeCell);
        const membershipSource = cleanText(sourceCell);
        const sourceLower = membershipSource.toLocaleLowerCase();
        const typeLower = membershipType.toLocaleLowerCase();

        // For Graph removal only the membership source matters: the device must
        // be a DIRECT member. Dynamic memberships cannot be removed manually.
        // Do not require the portal's localized membership type to equal a
        // specific word such as "Assigned"; Intune has used different labels
        // for static memberships in different ReactBlade builds/locales.
        const isTransitive = /transitiv|indirect|indirekt|nested|inherited|geerbt/.test(sourceLower);
        const isDirect = /direct|direkt/.test(sourceLower) && !isTransitive;
        const isDynamic = /dynamic|dynamisch/.test(typeLower);
        const removable = isDirect && !isDynamic;

        let disabledReason = '';
        if (isDynamic) {
            disabledReason = 'Dynamic group membership cannot be removed manually.';
        } else if (isTransitive) {
            disabledReason = 'Transitive/indirect membership: remove the device from the directly assigning group.';
        } else if (!isDirect) {
            disabledReason = `Membership source "${membershipSource || 'unknown'}" was not identified as a direct membership.`;
        }

        return {
            row,
            groupNameCell,
            groupId,
            name,
            membershipType,
            membershipSource,
            removable,
            disabledReason
        };
    }

    function applyNativeCommandColors(button) {
        if (!button) return;

        const label = button.querySelector('.ms-Button-label') || button.querySelector('[data-tm-dgm-label]');
        const icon = button.querySelector('i.ms-Icon, i[data-icon-name]');

        // Make the active command visually unambiguous. The cloned Fluent UI
        // command can otherwise retain a grey foreground from generated styles.
        // Use the portal/Fluent brand foreground instead of reusing that grey.
        const activeColor = getComputedStyle(document.documentElement).getPropertyValue('--colorButtonToolbardForeground').trim() || '#ffffff';

        button.style.setProperty('color', activeColor, 'important');
        button.style.setProperty('opacity', '1', 'important');

        if (label) {
            label.style.setProperty('color', activeColor, 'important');
            label.style.setProperty('opacity', '1', 'important');
            label.style.setProperty('font-weight', '400', 'important');
        }

        if (icon) {
            icon.style.setProperty('color', activeColor, 'important');
            icon.style.setProperty('opacity', '1', 'important');
        }
    }

    function updateButton() {
        const button = document.getElementById('tm-dgm-remove-button');
        if (!button) return;

        const count = selectedGroups.size;
        const disabled = busy || count === 0;

        const commandIcon = button.querySelector('i.ms-Icon, i[data-icon-name]');
        if (commandIcon) applyPortalXIcon(commandIcon);

        // Match the native Intune Remove Members command exactly: no HTML
        // disabled attribute; the visual/interaction state is represented by
        // "is-disabled" + aria-disabled + tabindex.
        button.disabled = false;
        button.removeAttribute('disabled');
        button.classList.remove('disabled', 'ms-Button--disabled', 'tm-dgm-command-disabled');

        if (disabled) {
            button.classList.add('is-disabled');
            button.setAttribute('aria-disabled', 'true');
            button.setAttribute('data-is-focusable', 'true');
            button.tabIndex = -1;
            button.style.removeProperty('pointer-events');
        } else {
            button.classList.remove('is-disabled');
            button.setAttribute('aria-disabled', 'false');
            button.setAttribute('data-is-focusable', 'true');
            button.tabIndex = 0;
            button.style.setProperty('opacity', '1', 'important');
            button.style.setProperty('pointer-events', 'auto', 'important');
            applyNativeCommandColors(button);
        }

        const label = button.querySelector('.ms-Button-label') || button.querySelector('[data-tm-dgm-label]');
        if (label) {
            label.textContent = busy
                ? 'Removing…'
                : count > 0
                    ? `Remove (${count})`
                    : 'Remove';
        }

        const stateKey = `${disabled ? 'disabled' : 'enabled'}:${count}:${busy ? 'busy' : 'idle'}`;
        if (button.dataset.tmDgmLastState !== stateKey) {
            button.dataset.tmDgmLastState = stateKey;
            log('Remove button state:', {
                enabled: !disabled,
                selected: count,
                busy,
                buttonColor: getComputedStyle(button).color,
                labelColor: label ? getComputedStyle(label).color : null,
                iconColor: (() => {
                    const icon = button.querySelector('i.ms-Icon, i[data-icon-name]');
                    return icon ? getComputedStyle(icon).color : null;
                })()
            });
        }
    }

    function injectCheckboxIntoRow(row) {
        const state = getMembershipState(row);
        if (!state) return;

        let wrapper = state.groupNameCell.querySelector('.tm-dgm-checkbox-wrap');
        let checkbox = wrapper && wrapper.querySelector('input.tm-dgm-checkbox');

        if (!wrapper || !checkbox) {
            wrapper = document.createElement('span');
            wrapper.className = 'tm-dgm-checkbox-wrap';
            wrapper.setAttribute('data-tm-dgm-checkbox', '1');

            checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'tm-dgm-checkbox';
            checkbox.setAttribute('aria-label', `Select group ${state.name}`);

            for (const eventName of ['click', 'mousedown', 'mouseup', 'dblclick']) {
                wrapper.addEventListener(eventName, event => event.stopPropagation());
            }

            checkbox.addEventListener('change', event => {
                event.stopPropagation();
                const id = checkbox.dataset.groupId;
                if (!id) return;

                if (checkbox.checked) {
                    selectedGroups.set(id, {
                        groupId: id,
                        name: checkbox.dataset.groupName || id
                    });
                } else {
                    selectedGroups.delete(id);
                }
                updateButton();
            });

            wrapper.appendChild(checkbox);
            state.groupNameCell.insertBefore(wrapper, state.groupNameCell.firstChild);
        }

        checkbox.dataset.groupId = state.groupId;
        checkbox.dataset.groupName = state.name;
        checkbox.dataset.removable = state.removable ? 'true' : 'false';
        checkbox.dataset.disabledReason = state.disabledReason || '';
        checkbox.disabled = !state.removable || busy;
        checkbox.checked = state.removable && selectedGroups.has(state.groupId);
        checkbox.title = state.removable ? 'Select group for removal' : state.disabledReason;
        wrapper.title = checkbox.title;

        if (!state.removable) {
            selectedGroups.delete(state.groupId);
        }
    }

    function sanitizeClonedElement(root) {
        if (root.id) root.removeAttribute('id');
        root.querySelectorAll('[id]').forEach(element => element.removeAttribute('id'));
        root.querySelectorAll('[aria-controls]').forEach(element => element.removeAttribute('aria-controls'));
        root.removeAttribute('aria-controls');
        root.removeAttribute('elementtiming');
        root.querySelectorAll('[elementtiming]').forEach(element => element.removeAttribute('elementtiming'));
    }

    function findButtonLabelElement(button) {
        const known = button.querySelector('[data-tm-dgm-label], .ms-Button-label');
        if (known) return known;

        const leaves = [...button.querySelectorAll('span, div')].filter(element =>
            element.children.length === 0 && /^(refresh|aktualisieren)$/i.test(cleanText(element))
        );
        return leaves[0] || null;
    }

    function applyPortalXIcon(targetIcon) {
        if (!targetIcon) return;

        // Exact icon used by the native Intune "Remove Members" command:
        // <i data-icon-name="Clear" style="font-family: FabricMDL2Icons;">\uE894</i>
        // Keep the generated Fluent classes from the cloned portal command, but
        // replace icon name, glyph and font with the native Remove template.
        [...targetIcon.classList]
            .filter(name => /^ms-Icon--/.test(name))
            .forEach(name => targetIcon.classList.remove(name));

        targetIcon.setAttribute('data-icon-name', 'Clear');
        targetIcon.dataset.iconName = 'Clear';
        targetIcon.textContent = '\uE894';
        targetIcon.style.setProperty('font-family', 'FabricMDL2Icons', 'important');
        targetIcon.dataset.tmPortalXSource = 'Intune native Clear/E894';
    }

    function configureToolbarButton(button) {
        sanitizeClonedElement(button);
        button.id = 'tm-dgm-remove-button';
        button.type = 'button';
        button.name = 'Remove';
        button.dataset.testid = 'remove-members';
        button.dataset.telemetryname = 'CommandBar - Remove Members';
        button.setAttribute('aria-label', 'Remove');
        button.removeAttribute('aria-haspopup');
        button.removeAttribute('aria-expanded');
        button.removeAttribute('aria-controls');
        button.removeAttribute('disabled');
        button.disabled = false;
        button.classList.remove('disabled', 'ms-Button--disabled', 'tm-dgm-command-disabled');
        button.classList.add('is-disabled');
        button.setAttribute('aria-disabled', 'true');
        button.setAttribute('data-is-focusable', 'true');
        button.tabIndex = -1;

        // Use the same Fluent/Fabric icon mechanism as the portal. Prefer a
        // native X icon that is already rendered somewhere in this ReactBlade;
        // that gives us the exact glyph and FabricMDL2Icons subset used here.
        const icon = button.querySelector('i.ms-Icon, i[data-icon-name]');
        if (icon) {
            applyPortalXIcon(icon);
        }

        let label = findButtonLabelElement(button);
        if (!label) {
            label = document.createElement('span');
            // Only used as a last resort. Normally we clone the real portal
            // label element, so all Fluent classes are retained unchanged.
            label.className = 'ms-Button-label';
            button.appendChild(label);
        }
        label.setAttribute('data-tm-dgm-label', '1');
        label.textContent = 'Remove';
        return button;
    }

    function applyPortalAddIcon(targetIcon) {
        if (!targetIcon) return;

        // Exact native Entra/Intune command-bar Add icon:
        // <i data-icon-name="Add" style="font-family: FabricMDL2Icons;">\uE710</i>
        [...targetIcon.classList]
            .filter(name => /^ms-Icon--/.test(name))
            .forEach(name => targetIcon.classList.remove(name));

        targetIcon.setAttribute('data-icon-name', 'Add');
        targetIcon.dataset.iconName = 'Add';
        targetIcon.textContent = '\uE710';
        targetIcon.style.setProperty('font-family', 'FabricMDL2Icons', 'important');
        targetIcon.dataset.tmPortalAddSource = 'Intune native Add/E710';
    }

    function configureAddToolbarButton(button) {
        sanitizeClonedElement(button);
        button.id = 'tm-dgm-add-button';
        button.type = 'button';
        button.name = 'Add members';
        button.dataset.testid = 'add-members';
        button.dataset.telemetryname = 'CommandBar - Add Members';
        button.setAttribute('aria-label', 'Add');
        button.removeAttribute('aria-haspopup');
        button.removeAttribute('aria-expanded');
        button.removeAttribute('aria-controls');
        button.removeAttribute('disabled');
        button.disabled = false;
        button.classList.remove('is-disabled', 'disabled', 'ms-Button--disabled');
        button.setAttribute('aria-disabled', 'false');
        button.setAttribute('data-is-focusable', 'true');
        button.tabIndex = 0;

        const icon = button.querySelector('i.ms-Icon, i[data-icon-name]');
        if (icon) applyPortalAddIcon(icon);

        let label = findButtonLabelElement(button);
        if (!label) {
            label = document.createElement('span');
            label.className = 'ms-Button-label';
            button.appendChild(label);
        }
        label.removeAttribute('data-tm-dgm-label');
        label.setAttribute('data-tm-dgm-add-label', '1');
        label.textContent = 'Add';

        const toolbarForeground = getComputedStyle(document.documentElement)
            .getPropertyValue('--colorButtonToolbardForeground').trim() || '#ffffff';
        button.style.setProperty('color', toolbarForeground, 'important');
        button.style.setProperty('cursor', 'pointer', 'important');
        button.style.setProperty('pointer-events', 'auto', 'important');
        label.style.setProperty('color', toolbarForeground, 'important');
        label.style.setProperty('cursor', 'pointer', 'important');
        if (icon) {
            icon.style.setProperty('color', toolbarForeground, 'important');
            icon.style.setProperty('cursor', 'pointer', 'important');
        }
        for (const child of button.querySelectorAll('span')) {
            child.style.setProperty('cursor', 'pointer', 'important');
        }
        return button;
    }

    function isElementVisible(element) {
        if (!element || !element.isConnected) return false;
        const style = getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        if (element.getAttribute('aria-hidden') === 'true') return false;
        return true;
    }

    function findNativeCommandTemplate() {
        // The DeviceGroupMembership ReactBlade currently renders native commands
        // exactly as Fluent UI v8 OverflowSet items, e.g.:
        //   <div class="ms-OverflowSet-item ...">
        //     <button class="ms-Button ms-Button--commandBar ..." role="menuitem">...</button>
        // Do not scope this search through __bladeCommandBar: in this ReactBlade
        // the element reported as the blade command bar is not necessarily the
        // DOM ancestor of the visible OverflowSet commands.
        const selector = 'div.ms-OverflowSet-item > button.ms-Button.ms-Button--commandBar[role="menuitem"]';
        const buttons = [...document.querySelectorAll(selector)]
            .filter(button => button.id !== 'tm-dgm-remove-button' && button.id !== 'tm-dgm-add-button')
            .filter(button => !button.closest('#tm-dgm-toolbar-item') && !button.closest('#tm-dgm-add-toolbar-item'))
            .filter(isElementVisible);

        if (!buttons.length) return null;

        // Prefer Refresh as the exact native template. This is the concrete
        // command observed in the DeviceGroupMembership blade and guarantees
        // that our enabled visual state is identical to an active portal command.
        const preferred = buttons.find(button =>
            button.matches('.automation-id-refresh') ||
            /^(refresh|aktualisieren)$/i.test(button.getAttribute('aria-label') || '') ||
            /^(refresh|aktualisieren)$/i.test(cleanText(button))
        ) || buttons.find(button =>
            button.matches('.automation-id-export') ||
            /^(export)$/i.test(button.getAttribute('aria-label') || '') ||
            /^(export)$/i.test(cleanText(button))
        ) || buttons[0];

        const item = preferred.parentElement;
        if (!item || !item.matches('div.ms-OverflowSet-item')) return null;

        return { button: preferred, item };
    }

    function makeCloneVisible(element) {
        if (!element) return;
        element.removeAttribute('hidden');
        if (element.getAttribute('aria-hidden') === 'true') {
            element.removeAttribute('aria-hidden');
        }
        if (element.style) {
            element.style.removeProperty('display');
            element.style.removeProperty('visibility');
            element.style.removeProperty('opacity');
        }
    }

    function attachRemoveButtonHandler(button) {
        button.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            event.stopImmediatePropagation();
            log(`Removal requested. Selected groups: ${selectedGroups.size}.`);
            removeSelectedGroups().catch(error => {
            warn('Unexpected error:', error);
                showToast(formatError(error), true, 9000);
            });
        }, true);
    }

    function captureNativeCommandColors(button) {
        const label = button && (button.querySelector('.ms-Button-label') || button.querySelector('[data-tm-dgm-label]'));
        const icon = button && button.querySelector('i.ms-Icon, i[data-icon-name]');
        return {
            buttonColor: button ? getComputedStyle(button).color : '',
            labelColor: label ? getComputedStyle(label).color : '',
            iconColor: icon ? getComputedStyle(icon).color : ''
        };
    }

    function storeNativeCommandColors(button, colors) {
        if (!button || !colors) return;
        if (colors.buttonColor) button.dataset.tmNativeButtonColor = colors.buttonColor;
        if (colors.labelColor) button.dataset.tmNativeLabelColor = colors.labelColor;
        if (colors.iconColor) button.dataset.tmNativeIconColor = colors.iconColor;
    }

    function ensureToolbarButton() {
        const existing = document.getElementById('tm-dgm-remove-button');
        if (existing) {
            updateButton();
            return;
        }
        if (!hasGroupMembershipColumns()) return;

        const template = findNativeCommandTemplate();
        if (!template) {
            warn('No Fluent command-bar button matching the expected ms-OverflowSet-item schema was found.');
            return;
        }

        // Capture the exact active foreground colors before cloning. These are
        // re-applied when our command becomes enabled so generated Fluent state
        // selectors cannot leave text/icon looking disabled.
        const nativeColors = captureNativeCommandColors(template.button);

        // Clone the complete native OverflowSet item. This preserves exactly
        // the portal's current wrapper class (item-xxx), spacing and button
        // classes (root-xxx/flexContainer-xxx/icon-xxx/label-xxx).
        const item = template.item.cloneNode(true);
        sanitizeClonedElement(item);
        item.id = 'tm-dgm-toolbar-item';
        makeCloneVisible(item);

        const clonedButton = item.querySelector('button.ms-Button.ms-Button--commandBar') || item.querySelector('button');
        if (!clonedButton) {
            warn('The cloned OverflowSet item does not contain a button.');
            return;
        }

        // Keep the native Fluent classes, but remove the source command's
        // semantic automation class so the clone is not mistaken for Export.
        [...clonedButton.classList]
            .filter(className => /^automation-id-/i.test(className))
            .forEach(className => clonedButton.classList.remove(className));

        const button = configureToolbarButton(clonedButton);
        storeNativeCommandColors(button, nativeColors);
        makeCloneVisible(button);
        applyNativeCommandColors(button);
        attachRemoveButtonHandler(button);

        template.item.insertAdjacentElement('afterend', item);

        log('Button "Remove from groups" inserted as a native ms-OverflowSet item directly after',
            template.button.getAttribute('aria-label') || cleanText(template.button) || 'Portal-Command',
            'the template item.');
        updateButton();
    }

    function ensureAddToolbarButton() {
        if (document.getElementById('tm-dgm-add-button')) return;
        if (!hasGroupMembershipColumns()) return;

        const template = findNativeCommandTemplate();
        if (!template) return;

        const item = template.item.cloneNode(true);
        sanitizeClonedElement(item);
        item.id = 'tm-dgm-add-toolbar-item';
        makeCloneVisible(item);

        const clonedButton = item.querySelector('button.ms-Button.ms-Button--commandBar') || item.querySelector('button');
        if (!clonedButton) return;

        [...clonedButton.classList]
            .filter(className => /^automation-id-/i.test(className))
            .forEach(className => clonedButton.classList.remove(className));
        clonedButton.classList.add('automation-id-tm-add-groups');

        const button = configureAddToolbarButton(clonedButton);
        makeCloneVisible(button);
        button.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            event.stopImmediatePropagation();
            openAddPopover();
        }, true);

        // Put Add immediately after the native template. Since Remove is also
        // inserted after that template, Add ends up directly before Remove.
        template.item.insertAdjacentElement('afterend', item);
        log('Button "Add" inserted as a native ms-OverflowSet item.');
    }

    function logDomDiagnostics() {
        if (!context.isDeviceGroupMembershipFrame) return;
        if (document.documentElement.dataset.tmDgmDiagnosticsLogged === 'true') return;
        document.documentElement.dataset.tmDgmDiagnosticsLogged = 'true';

        const keys = [...document.querySelectorAll('[data-automation-key]')]
            .map(element => element.getAttribute('data-automation-key'))
            .filter(Boolean);
        const uniqueKeys = [...new Set(keys)];

        log('DeviceGroupMembership-Frame bestätigt, DOM-Diagnose:', {
            groupName: document.querySelectorAll('[data-automation-key="groupName"]').length,
            objectID: document.querySelectorAll('[data-automation-key="objectID"]').length,
            membershipType: document.querySelectorAll('[data-automation-key="localizedMembershipTypeString"]').length,
            membershipSource: document.querySelectorAll('[data-automation-key="localizedMembershipSourceString"]').length,
            automationKeys: uniqueKeys.slice(0, 80),
            commandBar: !!(document.getElementById('__bladeCommandBar') ||
                document.querySelector('[data-testid="command-bar"], [data-automationid="CommandBar"], .ms-CommandBar')),
            observedEntraDeviceId: context.entraDeviceId || observedEntraDeviceId || null
        });
    }

    function renderUi() {
        renderQueued = false;
        addStyle();

        // The parent portal does not always expose the iframe name to the
        // sandboxed ReactBlade. The characteristic four-column DOM is enough
        // to identify this view safely.
        if (!context.isDeviceGroupMembershipFrame && hasGroupMembershipColumns()) {
            context.isDeviceGroupMembershipFrame = true;
            log('DeviceGroupMembership identified from the loaded group DOM.');
        }

        // Insert the command immediately when the async membership search has
        // rendered the four characteristic columns. This is intentionally
        // independent of row/GUID parsing.
        if (hasGroupMembershipColumns()) {
            ensureToolbarButton();
            ensureAddToolbarButton();
        }

        const rows = findGroupRows();
        if (rows.length === 0) {
            if (context.isDeviceGroupMembershipFrame) {
                window.setTimeout(logDomDiagnostics, 1200);
            }
            return;
        }

        let recognized = 0;
        rows.forEach(row => {
            if (getMembershipState(row)) {
                injectCheckboxIntoRow(row);
                recognized++;
            }
        });

        if (recognized > 0) {
            updateButton();
            if (!document.documentElement.dataset.tmDgmGridDetected) {
                document.documentElement.dataset.tmDgmGridDetected = 'true';
                log(`Group grid detected: ${recognized} row(s).`);
            }
        } else if (!document.documentElement.dataset.tmDgmRowParseLogged) {
            document.documentElement.dataset.tmDgmRowParseLogged = 'true';
            const first = rows[0];
            log('Group columns found, but rows could not be evaluated yet. First values:', {
                groupName: cleanText(getCell(first, 'groupName')),
                objectID: cleanText(getCell(first, 'objectID')),
                membershipType: cleanText(getCell(first, 'localizedMembershipTypeString')),
                membershipSource: cleanText(getCell(first, 'localizedMembershipSourceString')),
                extractedObjectID: extractGuidFromElement(getCell(first, 'objectID'))
            });
        }
    }

    function queueRender() {
        if (renderQueued) return;
        renderQueued = true;
        window.requestAnimationFrame(renderUi);
    }

    function startObserver() {
        if (observer || !document.body) return;
        observer = new MutationObserver(queueRender);
        observer.observe(document.body, { childList: true, subtree: true });
        queueRender();
    }

    class GraphRequestError extends Error {
        constructor(message, status, responseText, url) {
            super(message);
            this.name = 'GraphRequestError';
            this.status = status;
            this.responseText = responseText || '';
            this.url = url;
        }
    }

    function parseGraphError(responseText) {
        if (!responseText) return '';
        try {
            const json = JSON.parse(responseText);
            return json && json.error && (json.error.message || json.error.code)
                ? `${json.error.code ? `${json.error.code}: ` : ''}${json.error.message || ''}`.trim()
                : responseText;
        } catch (_) {
            return responseText;
        }
    }

    async function browserGraphRequest(method, url, token, options = {}) {
        const relative = (() => {
            try {
                const parsed = new URL(url);
                return `${parsed.pathname}${parsed.search}`;
            } catch (_) {
                return url;
            }
        })();

        log(`Graph -> ${method} ${relative}`);
        let response;
        try {
            const headers = {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
                ...(options.headers || {})
            };
            let body;
            if (options.body !== undefined && options.body !== null) {
                body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
                if (!Object.keys(headers).some(key => key.toLowerCase() === 'content-type')) {
                    headers['Content-Type'] = 'application/json';
                }
            }
            response = await pageWindow.fetch(url, {
                method,
                headers,
                body,
                mode: 'cors',
                credentials: 'omit',
                cache: 'no-store'
            });
        } catch (error) {
            warn(`Graph browser fetch failed (${method} ${relative}); using the GM_xmlhttpRequest fallback:`, error);
            return gmGraphRequestFallback(method, url, token, relative, options);
        }

        const status = Number(response.status || 0);
        const responseText = await response.text();
        log(`Graph <- HTTP ${status} ${method} ${relative}`);

        if (status >= 200 && status < 300) {
            let data = null;
            if (responseText) {
                try { data = JSON.parse(responseText); } catch (_) { data = responseText; }
            }
            return { status, data, responseText };
        }

        throw new GraphRequestError(
            parseGraphError(responseText) || `Microsoft Graph antwortete mit HTTP ${status}.`,
            status,
            responseText,
            url
        );
    }

    function gmGraphRequestFallback(method, url, token, relative = url, options = {}) {
        return new Promise((resolve, reject) => {
            const headers = {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
                ...(options.headers || {})
            };
            let data;
            if (options.body !== undefined && options.body !== null) {
                data = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
                if (!Object.keys(headers).some(key => key.toLowerCase() === 'content-type')) {
                    headers['Content-Type'] = 'application/json';
                }
            }
            GM_xmlhttpRequest({
                method,
                url,
                headers,
                data,
                timeout: 30000,
                onload: response => {
                    const status = Number(response.status || 0);
                    log(`Graph(GM) <- HTTP ${status} ${method} ${relative}`);
                    if (status >= 200 && status < 300) {
                        let data = null;
                        if (response.responseText) {
                            try { data = JSON.parse(response.responseText); } catch (_) { data = response.responseText; }
                        }
                        resolve({ status, data, responseText: response.responseText || '' });
                        return;
                    }
                    reject(new GraphRequestError(
                        parseGraphError(response.responseText) || `Microsoft Graph antwortete mit HTTP ${status}.`,
                        status,
                        response.responseText,
                        url
                    ));
                },
                ontimeout: () => reject(new GraphRequestError('The Microsoft Graph request timed out.', 0, '', url)),
                onerror: response => reject(new GraphRequestError('The Microsoft Graph request failed.', Number(response && response.status || 0), response && response.responseText || '', url))
            });
        });
    }

    async function waitForTokens(timeoutMs = 5000) {
        const end = Date.now() + timeoutMs;
        scanMsalSessionStorageAccessTokens(true);
        scanStorageForGraphTokens(true);
        requestContext();

        while (Date.now() < end) {
            if (rankTokens().length > 0) return;
            await new Promise(resolve => setTimeout(resolve, 250));
            requestContext();
        }

        throw new Error('No Microsoft Graph token detected. Fully reload Intune once so the script can observe portal requests from document-start.');
    }

    async function graphRequestWithAvailableTokens(method, url, preferredScopes = [], options = {}) {
        if (rankTokens().length === 0) await waitForTokens();

        const ranked = rankTokens(preferredScopes);
        if (ranked.length === 0) {
            throw new Error('No valid Microsoft Graph token is available.');
        }

        const preferred = new Set(preferredScopes.map(value => value.toLowerCase()));
        const matching = ranked.filter(entry => entry.scopes.some(scope => preferred.has(scope.toLowerCase())));
        const opaque = ranked.filter(entry => entry.scopes.length === 0);
        // If a token explicitly advertises a required/compatible scope, do not
        // waste time cycling through unrelated User.Read/Organization tokens.
        const candidates = matching.length > 0
            ? [...matching, ...opaque.filter(entry => !matching.includes(entry))]
            : ranked;

        log(`Graph ${method}: ${candidates.length} geeignete Token-Kandidat(en).`);
        let lastAuthError = null;
        for (let index = 0; index < candidates.length; index++) {
            const candidate = candidates[index];
            const scopeInfo = candidate.scopes.length ? candidate.scopes.join(', ') : '(opaque)';
            log(`Graph Token ${index + 1}/${candidates.length}: ${scopeInfo}`);
            try {
                return await browserGraphRequest(method, url, candidate.token, options);
            } catch (error) {
                if (error instanceof GraphRequestError && (error.status === 401 || error.status === 403)) {
                    lastAuthError = error;
                    warn(`Token ${index + 1}/${candidates.length} abgelehnt: HTTP ${error.status}.`);
                    continue;
                }
                throw error;
            }
        }

        throw lastAuthError || new Error('None of the detected Microsoft Graph tokens could be used for this request.');
    }

    async function waitForManagedDeviceId(timeoutMs = 4000) {
        if (context.managedDeviceId) return context.managedDeviceId;
        const end = Date.now() + timeoutMs;

        while (Date.now() < end) {
            requestContext();
            await new Promise(resolve => setTimeout(resolve, 200));
            if (context.managedDeviceId) return context.managedDeviceId;
        }

        throw new Error('The managedDeviceId could not be determined from the Intune device URL.');
    }

    async function resolveDirectoryDeviceByDeviceId(azureAdDeviceId, fallbackName = '') {
        const deviceUrl = `${GRAPH_ORIGIN}/v1.0/devices(deviceId='${azureAdDeviceId}')?$select=id,deviceId,displayName`;
        const deviceResponse = await graphRequestWithAvailableTokens('GET', deviceUrl, [
            'Directory.AccessAsUser.All',
            'Device.Read.All',
            'Directory.Read.All',
            'Directory.ReadWrite.All'
        ]);

        const device = deviceResponse.data || {};
        if (!device.id || !GUID_RE.test(device.id)) {
            throw new Error('The Entra device object ID could not be determined.');
        }

        return {
            azureAdDeviceId,
            objectId: device.id,
            displayName: device.displayName || fallbackName || azureAdDeviceId
        };
    }

    async function resolveDeviceObject() {
        // Preferred path: the membership blade already knows the Entra deviceId
        // and uses it in its own asynchronous query (filter=deviceId eq '...').
        // Reuse that value and avoid an unnecessary Intune managedDevice lookup.
        const observedDeviceId = context.entraDeviceId || observedEntraDeviceId;
        if (observedDeviceId && GUID_RE.test(observedDeviceId)) {
            log('Using Entra deviceId from the group search request:', observedDeviceId);
            const directoryDevice = await resolveDirectoryDeviceByDeviceId(observedDeviceId);
            return {
                managedDeviceId: context.managedDeviceId || null,
                ...directoryDevice
            };
        }

        // Fallback for portal builds where the membership request was already
        // completed before the document-start hook could observe it.
        const managedDeviceId = await waitForManagedDeviceId();
        log('No deviceId was found in the group request; resolving through managedDeviceId:', managedDeviceId);

        const managedUrl = `${GRAPH_ORIGIN}/v1.0/deviceManagement/managedDevices/${managedDeviceId}?$select=id,deviceName,azureADDeviceId`;
        const managedResponse = await graphRequestWithAvailableTokens('GET', managedUrl, [
            'DeviceManagementManagedDevices.Read.All',
            'DeviceManagementManagedDevices.ReadWrite.All'
        ]);

        const managed = managedResponse.data || {};
        const azureAdDeviceId = managed.azureADDeviceId;
        if (!azureAdDeviceId || !GUID_RE.test(azureAdDeviceId)) {
            throw new Error(`The Intune device ${managed.deviceName || managedDeviceId} did not return a valid azureADDeviceId.`);
        }

        const directoryDevice = await resolveDirectoryDeviceByDeviceId(azureAdDeviceId, managed.deviceName || managedDeviceId);
        return {
            managedDeviceId,
            ...directoryDevice
        };
    }

    async function deleteMembership(groupId, deviceObjectId) {
        const url = `${GRAPH_ORIGIN}/v1.0/groups/${groupId}/members/${deviceObjectId}/$ref`;
        await graphRequestWithAvailableTokens('DELETE', url, [
            'Directory.AccessAsUser.All',
            'GroupMember.ReadWrite.All',
            'Group.ReadWrite.All',
            'Directory.ReadWrite.All'
        ]);
    }

    function splitGroupSearchTerms(value) {
        return [...new Set(String(value || '')
            .trim()
            .split(/\s+/)
            .map(term => term.toLocaleLowerCase())
            .filter(Boolean))];
    }

    function groupMatchesSearchTerms(groupName, terms) {
        const name = String(groupName || '').toLocaleLowerCase();
        return terms.length > 0 && terms.every(term => name.includes(term));
    }

    function escapeGraphSearchTerm(value) {
        return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    function getCurrentDirectMembershipIds() {
        const ids = new Set();
        for (const row of findGroupRows()) {
            const state = getMembershipState(row);
            if (!state) continue;
            const source = String(state.membershipSource || '').toLocaleLowerCase();
            const transitive = /transitiv|indirect|indirekt|nested|inherited|geerbt/.test(source);
            const direct = /direct|direkt/.test(source) && !transitive;
            if (direct) ids.add(state.groupId.toLowerCase());
        }
        return ids;
    }

    function isDynamicGroup(group) {
        return Array.isArray(group && group.groupTypes) &&
            group.groupTypes.some(value => String(value).toLocaleLowerCase() === 'dynamicmembership');
    }

    async function searchGroupsForAdd(query, sequence) {
        const terms = splitGroupSearchTerms(query);
        if (terms.length === 0) return [];

        // Graph narrows the candidate set with one term; exact AND-substring
        // semantics are enforced client-side below for every whitespace token.
        const serverTerm = [...terms].sort((a, b) => b.length - a.length)[0];
        const searchExpression = `"displayName:${escapeGraphSearchTerm(serverTerm)}"`;
        let url = `${GRAPH_ORIGIN}/v1.0/groups?` +
            `$search=${encodeURIComponent(searchExpression)}` +
            `&$select=id,displayName,groupTypes,securityEnabled,mailEnabled,membershipRule` +
            `&$top=100`;

        const found = new Map();
        let page = 0;
        while (url && page < 3 && found.size < 100) {
            if (sequence !== addSearchSequence) return [];
            const response = await graphRequestWithAvailableTokens('GET', url, [
                'Directory.AccessAsUser.All',
                'Group.Read.All',
                'Directory.Read.All',
                'Directory.ReadWrite.All'
            ], {
                headers: { ConsistencyLevel: 'eventual' }
            });

            const data = response.data || {};
            for (const group of Array.isArray(data.value) ? data.value : []) {
                if (!group || !GUID_RE.test(String(group.id || ''))) continue;
                if (!groupMatchesSearchTerms(group.displayName, terms)) continue;
                found.set(String(group.id).toLowerCase(), group);
            }

            url = typeof data['@odata.nextLink'] === 'string' ? data['@odata.nextLink'] : null;
            page++;
        }

        return [...found.values()]
            .sort((a, b) => String(a.displayName || '').localeCompare(String(b.displayName || ''), undefined, { sensitivity: 'base' }))
            .slice(0, 100);
    }

    function getAddPopoverElements() {
        const overlay = document.getElementById('tm-dgm-add-popover-overlay');
        return {
            overlay,
            popover: document.getElementById('tm-dgm-add-popover'),
            input: document.getElementById('tm-dgm-group-search'),
            clearButton: document.getElementById('tm-dgm-search-clear'),
            status: document.getElementById('tm-dgm-search-status'),
            results: document.getElementById('tm-dgm-search-results'),
            selectedTitle: document.getElementById('tm-dgm-selected-title'),
            selectedList: document.getElementById('tm-dgm-selected-list'),
            resetButton: document.getElementById('tm-dgm-selected-reset'),
            applyButton: document.getElementById('tm-dgm-add-apply')
        };
    }

    function getGroupInitials(name) {
        const words = String(name || '')
            .trim()
            .split(/[\s_\-\/]+/)
            .filter(Boolean);
        if (!words.length) return 'G';
        if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
        return (words[0][0] + words[1][0]).toUpperCase();
    }

    function renderPendingAddGroups() {
        const { selectedTitle, selectedList, resetButton, applyButton } = getAddPopoverElements();
        if (!selectedTitle || !selectedList || !resetButton || !applyButton) return;

        selectedTitle.textContent = `Selected (${pendingAddGroups.size})`;
        selectedList.textContent = '';

        if (pendingAddGroups.size === 0) {
            const empty = document.createElement('div');
            empty.className = 'tm-dgm-selected-empty';
            empty.textContent = 'No items selected';
            selectedList.appendChild(empty);
        } else {
            for (const group of pendingAddGroups.values()) {
                const row = document.createElement('div');
                row.className = 'tm-dgm-selected-row';
                row.title = `${group.displayName}\n${group.id}`;

                const icon = document.createElement('div');
                icon.className = 'tm-dgm-selected-icon';
                icon.textContent = getGroupInitials(group.displayName);

                const name = document.createElement('div');
                name.className = 'tm-dgm-selected-name';
                name.textContent = group.displayName;

                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'tm-dgm-selected-remove';
                remove.setAttribute('aria-label', `${group.displayName} remove from selection`);
                remove.innerHTML = '<i data-icon-name="Clear" aria-hidden="true">\uE894</i>';
                remove.addEventListener('click', event => {
                    event.preventDefault();
                    event.stopPropagation();
                    if (addBusy) return;
                    pendingAddGroups.delete(group.id.toLowerCase());
                    renderPendingAddGroups();
                    renderAddSearchResults(addSearchResults);
                });

                row.append(icon, name, remove);
                selectedList.appendChild(row);
            }
        }

        resetButton.disabled = addBusy || pendingAddGroups.size === 0;
        applyButton.disabled = addBusy || pendingAddGroups.size === 0;
        const applyLabel = applyButton.querySelector('.ms-Button-label') || applyButton;
        applyLabel.textContent = addBusy ? 'Adding…' : 'Select';
    }

    function createNativePickerCheckbox(selected, disabled) {
        const checkHost = document.createElement('div');
        checkHost.className = 'tm-dgm-native-check';
        checkHost.setAttribute('role', 'checkbox');
        checkHost.setAttribute('aria-checked', selected ? 'true' : 'false');
        if (disabled) checkHost.setAttribute('aria-disabled', 'true');

        const circle = document.createElement('i');
        circle.className = 'tm-dgm-check-circle';
        circle.setAttribute('data-icon-name', 'CircleRing');
        circle.setAttribute('aria-hidden', 'true');
        circle.textContent = '\uEA3A';

        const mark = document.createElement('i');
        mark.className = 'tm-dgm-check-mark';
        mark.setAttribute('data-icon-name', 'StatusCircleCheckmark');
        mark.setAttribute('aria-hidden', 'true');
        mark.textContent = '\uF13E';

        checkHost.append(circle, mark);
        return checkHost;
    }

    function renderAddSearchResults(groups) {
        const { results, status } = getAddPopoverElements();
        if (!results || !status) return;

        results.textContent = '';
        const query = lastAddSearchQuery.trim();

        if (!query) {
            status.textContent = '';
            const empty = document.createElement('div');
            empty.className = 'tm-dgm-empty';
            empty.textContent = 'Start typing to search groups.';
            results.appendChild(empty);
            return;
        }

        status.textContent = `${groups.length} result${groups.length === 1 ? '' : 's'} found`;
        if (groups.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'tm-dgm-empty';
            empty.textContent = 'No matching groups found.';
            results.appendChild(empty);
            return;
        }

        const currentDirectIds = getCurrentDirectMembershipIds();

        for (const group of groups) {
            const id = String(group.id).toLowerCase();
            const dynamic = isDynamicGroup(group);
            const securityGroup = group.securityEnabled === true;
            const alreadyDirect = currentDirectIds.has(id);
            const selected = pendingAddGroups.has(id);
            const disabled = addBusy || dynamic || !securityGroup || alreadyDirect;

            const row = document.createElement('div');
            row.className = 'tm-dgm-picker-row';
            row.setAttribute('role', 'row');
            row.setAttribute('aria-selected', selected ? 'true' : 'false');
            if (selected) row.classList.add('is-selected');
            if (disabled) {
                row.classList.add('is-disabled');
                row.setAttribute('aria-disabled', 'true');
            }

            const checkCell = document.createElement('div');
            checkCell.className = 'tm-dgm-picker-cell tm-dgm-native-check-cell';
            checkCell.appendChild(createNativePickerCheckbox(selected, disabled));

            const nameCell = document.createElement('div');
            nameCell.className = 'tm-dgm-picker-cell tm-dgm-picker-cell-name';
            nameCell.textContent = group.displayName || id;
            nameCell.title = group.displayName || id;

            const typeCell = document.createElement('div');
            typeCell.className = 'tm-dgm-picker-cell';
            typeCell.textContent = 'Group';

            const detailsCell = document.createElement('div');
            detailsCell.className = 'tm-dgm-picker-cell tm-dgm-picker-cell-details';
            detailsCell.textContent = dynamic
                ? 'Dynamic groups cannot be modified manually.'
                : !securityGroup
                    ? 'Microsoft 365 groups are not allowed.'
                    : alreadyDirect
                        ? 'Device is already a direct member.'
                        : '';

            const toggleSelection = () => {
                if (disabled || addBusy) return;
                if (pendingAddGroups.has(id)) {
                    pendingAddGroups.delete(id);
                } else {
                    pendingAddGroups.set(id, {
                        id,
                        displayName: group.displayName || id,
                        securityEnabled: group.securityEnabled,
                        groupTypes: group.groupTypes || []
                    });
                }
                renderPendingAddGroups();
                renderAddSearchResults(addSearchResults);
            };

            row.addEventListener('click', toggleSelection);
            row.addEventListener('keydown', event => {
                if (event.key === ' ' || event.key === 'Enter') {
                    event.preventDefault();
                    toggleSelection();
                }
            });
            if (!disabled) row.tabIndex = 0;

            row.append(checkCell, nameCell, typeCell, detailsCell);
            results.appendChild(row);
        }
    }

    function scheduleAddGroupSearch(value) {
        lastAddSearchQuery = String(value || '');
        if (addSearchTimer) window.clearTimeout(addSearchTimer);
        const sequence = ++addSearchSequence;
        const { status, results } = getAddPopoverElements();

        if (!lastAddSearchQuery.trim()) {
            addSearchResults = [];
            renderAddSearchResults([]);
            return;
        }

        if (status) status.textContent = 'Waiting for input…';
        addSearchTimer = window.setTimeout(async () => {
            if (sequence !== addSearchSequence) return;
            if (status) status.textContent = 'Searching…';
            if (results) {
                results.textContent = '';
                const loading = document.createElement('div');
                loading.className = 'tm-dgm-empty';
                loading.textContent = 'Searching Microsoft Entra groups…';
                results.appendChild(loading);
            }

            try {
                scanMsalSessionStorageAccessTokens(true);
                scanStorageForGraphTokens(true);
                const groups = await searchGroupsForAdd(lastAddSearchQuery, sequence);
                if (sequence !== addSearchSequence) return;
                addSearchResults = groups;
                renderAddSearchResults(groups);
            } catch (error) {
                if (sequence !== addSearchSequence) return;
                warn('Group search failed:', error);
                if (status) status.textContent = 'Search failed.';
                if (results) {
                    results.textContent = '';
                    const failed = document.createElement('div');
                    failed.className = 'tm-dgm-empty';
                    failed.textContent = formatError(error);
                    results.appendChild(failed);
                }
            }
        }, 450);
    }

    function closeAddPopover() {
        ++addSearchSequence;
        if (addSearchTimer) {
            window.clearTimeout(addSearchTimer);
            addSearchTimer = null;
        }
        document.getElementById('tm-dgm-add-popover-overlay')?.remove();
        pendingAddGroups.clear();
        addSearchResults = [];
        lastAddSearchQuery = '';
    }

    function openAddPopover() {
        if (document.getElementById('tm-dgm-add-popover-overlay')) return;
        addStyle();
        pendingAddGroups.clear();
        addSearchResults = [];
        lastAddSearchQuery = '';

        const overlay = document.createElement('div');
        overlay.id = 'tm-dgm-add-popover-overlay';
        overlay.innerHTML = `
            <div id="tm-dgm-add-popover" role="dialog" aria-modal="true" aria-labelledby="tm-dgm-add-title">
                <div class="tm-dgm-picker-titlebar">
                    <h2 class="tm-dgm-picker-title" id="tm-dgm-add-title">Add to groups</h2>
                    <button type="button" class="tm-dgm-picker-close" id="tm-dgm-add-close" aria-label="Close">
                        <i data-icon-name="Clear" aria-hidden="true">\uE894</i>
                    </button>
                </div>

                <div class="tm-dgm-picker-main">
                    <div class="tm-dgm-picker-left">
                        <div class="tm-dgm-picker-message">
                            <i data-icon-name="Info" aria-hidden="true">\uE946</i>
                            <span>Try changing or adding search terms if you don't see what you're looking for.</span>
                        </div>

                        <label class="tm-dgm-search-label" for="tm-dgm-group-search">Search</label>
                        <div class="tm-dgm-native-searchbox ms-SearchBox can-clear" role="search" aria-label="Search">
                            <i class="tm-dgm-native-search-icon ms-SearchBox-icon" data-icon-name="Search" aria-hidden="true">\uE721</i>
                            <input id="tm-dgm-group-search" class="ms-SearchBox-field" type="text" autocomplete="off" spellcheck="false" aria-label="Search groups">
                            <button type="button" class="tm-dgm-search-clear" id="tm-dgm-search-clear" aria-label="Clear text">
                                <i data-icon-name="Clear" aria-hidden="true">\uE894</i>
                            </button>
                        </div>

                        <div class="tm-dgm-search-status" id="tm-dgm-search-status" role="status" aria-live="polite"></div>

                        <div class="tm-dgm-picker-pivot" role="tablist">
                            <button type="button" class="tm-dgm-picker-pivot-button" role="tab" aria-selected="true">Groups</button>
                        </div>

                        <div class="tm-dgm-results-shell">
                            <div class="tm-dgm-results-header" role="row">
                                <div></div>
                                <div>Name</div>
                                <div>Type</div>
                                <div>Details</div>
                            </div>
                            <div class="tm-dgm-results" id="tm-dgm-search-results" role="grid" aria-label="Group search results"></div>
                        </div>
                    </div>

                    <div class="tm-dgm-picker-cart">
                        <div class="tm-dgm-selected-header">
                            <h3 class="tm-dgm-selected-title" id="tm-dgm-selected-title" aria-live="polite">Selected (0)</h3>
                            <button type="button" class="tm-dgm-reset-button" id="tm-dgm-selected-reset" aria-label="Reset selection">
                                <i data-icon-name="Undo" aria-hidden="true">\uE7A7</i>
                                <span>Reset</span>
                            </button>
                        </div>
                        <div class="tm-dgm-selected-list" id="tm-dgm-selected-list"></div>
                    </div>
                </div>

                <div class="tm-dgm-add-footer">
                    <button type="button" class="ms-Button ms-Button--primary" id="tm-dgm-add-apply" data-is-focusable="true" disabled>
                        <span class="ms-Button-flexContainer" data-automationid="splitbuttonprimary">
                            <span class="ms-Button-textContainer">
                                <span class="ms-Button-label">Select</span>
                            </span>
                        </span>
                    </button>
                </div>
            </div>`;

        document.body.appendChild(overlay);
        const elements = getAddPopoverElements();
        renderPendingAddGroups();
        renderAddSearchResults([]);

        document.getElementById('tm-dgm-add-close').addEventListener('click', closeAddPopover);

        overlay.addEventListener('mousedown', event => {
            if (event.target === overlay && !addBusy) closeAddPopover();
        });

        elements.input.addEventListener('input', event => {
            elements.clearButton.style.visibility = event.target.value ? 'visible' : 'hidden';
            scheduleAddGroupSearch(event.target.value);
        });

        elements.input.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !addBusy) closeAddPopover();
        });

        elements.clearButton.style.visibility = 'hidden';
        elements.clearButton.addEventListener('click', () => {
            if (addBusy) return;
            elements.input.value = '';
            elements.clearButton.style.visibility = 'hidden';
            scheduleAddGroupSearch('');
            elements.input.focus();
        });

        elements.resetButton.addEventListener('click', () => {
            if (addBusy || pendingAddGroups.size === 0) return;
            pendingAddGroups.clear();
            renderPendingAddGroups();
            renderAddSearchResults(addSearchResults);
        });

        elements.applyButton.addEventListener('click', () => {
            addSelectedGroups().catch(error => {
                warn('Unexpected error while adding:', error);
                showToast(formatError(error), true, 9000);
            });
        });

        window.setTimeout(() => elements.input.focus(), 0);
    }

    async function addMembership(groupId, deviceObjectId) {
        const url = `${GRAPH_ORIGIN}/v1.0/groups/${groupId}/members/$ref`;
        await graphRequestWithAvailableTokens('POST', url, [
            'Directory.AccessAsUser.All',
            'GroupMember.ReadWrite.All',
            'Group.ReadWrite.All',
            'Directory.ReadWrite.All'
        ], {
            body: {
                '@odata.id': `${GRAPH_ORIGIN}/v1.0/directoryObjects/${deviceObjectId}`
            }
        });
    }

    async function addSelectedGroups() {
        if (addBusy || pendingAddGroups.size === 0) return;
        const groups = [...pendingAddGroups.values()];
        addBusy = true;
        renderPendingAddGroups();

        const input = document.getElementById('tm-dgm-group-search');
        if (input) input.disabled = true;
        const close = document.getElementById('tm-dgm-add-close');
        if (close) close.disabled = true;

        const results = [];
        try {
            scanMsalSessionStorageAccessTokens(true);
            scanStorageForGraphTokens(true);
            log(`Add confirmed. Processing ${groups.length} group(s).`);
            const device = await resolveDeviceObject();
            log('Resolved Entra device for add:', device);

            for (let index = 0; index < groups.length; index++) {
                const group = groups[index];
                const applyButton = document.getElementById('tm-dgm-add-apply');
                if (applyButton) {
                    const applyLabel = applyButton.querySelector('.ms-Button-label') || applyButton;
                    applyLabel.textContent = `Adding (${index + 1}/${groups.length})…`;
                }
                try {
                    await addMembership(group.id, device.objectId);
                    results.push({ ...group, success: true });
                    pendingAddGroups.delete(group.id.toLowerCase());
                    log(`Added device to group ${group.displayName} (${group.id}).`);
                } catch (error) {
                    results.push({ ...group, success: false, error });
                    warn(`Failed to add to ${group.displayName} (${group.id}):`, error);
                }
            }

            const successes = results.filter(result => result.success);
            const failures = results.filter(result => !result.success);

            if (successes.length > 0) {
                showToast(`${device.displayName}: added to ${successes.length} group${successes.length === 1 ? '' : 's'}.`);
            }
            if (failures.length > 0) {
                const details = failures.slice(0, 10)
                    .map(result => `• ${result.displayName}: ${formatError(result.error)}`)
                    .join('\n');
                showToast(`${failures.length} group${failures.length === 1 ? '' : 's'} could not be added:\n${details}`, true, 12000);
            }

            if (successes.length > 0) {
                closeAddPopover();
                schedulePortalRefreshAfterMembershipChange('Add');
            } else {
                renderPendingAddGroups();
                renderAddSearchResults(addSearchResults);
            }
        } finally {
            addBusy = false;
            const liveInput = document.getElementById('tm-dgm-group-search');
            if (liveInput) liveInput.disabled = false;
            const liveClose = document.getElementById('tm-dgm-add-close');
            if (liveClose) liveClose.disabled = false;
            renderPendingAddGroups();
        }
    }

    function setUiBusy(value) {
        busy = value;
        document.querySelectorAll('input.tm-dgm-checkbox').forEach(checkbox => {
            // Do not rediscover the Fluent UI row here. Current ReactBlade can
            // split logical row cells across different DOM branches.
            checkbox.disabled = value || checkbox.dataset.removable !== 'true';
        });
        updateButton();
    }

    function formatError(error) {
        if (error instanceof GraphRequestError) {
            if (error.status === 401) {
                return `Microsoft Graph: HTTP 401 - the detected portal token is no longer valid.\n${error.message}`;
            }
            if (error.status === 403) {
                return `Microsoft Graph: HTTP 403 - the signed-in user or detected token does not have sufficient group write permission for this action.\n${error.message}`;
            }
            return `Microsoft Graph: HTTP ${error.status || '?'} – ${error.message}`;
        }
        return error && error.message ? error.message : String(error);
    }

    function findPortalRefreshButton() {
        const selectors = [
            'div.ms-OverflowSet-item > button.ms-Button.ms-Button--commandBar.automation-id-refresh[role="menuitem"]',
            'button.ms-Button.ms-Button--commandBar.automation-id-refresh',
            'button.automation-id-refresh'
        ];

        for (const selector of selectors) {
            const button = [...document.querySelectorAll(selector)].find(candidate =>
                candidate.id !== 'tm-dgm-remove-button' && isElementVisible(candidate)
            );
            if (button) return button;
        }
        return null;
    }

    function schedulePortalRefreshAfterMembershipChange(operation) {
        log(`${operation}: waiting ${GROUP_REFRESH_DELAY_MS} ms for the group change to propagate before triggering Intune refresh.`);
        window.setTimeout(() => {
            log(`${operation}: propagation wait finished; triggering the native Intune refresh now.`);
            clickPortalRefreshButton();
        }, GROUP_REFRESH_DELAY_MS);
    }

    function clickPortalRefreshButton() {
        const refresh = findPortalRefreshButton();
        if (!refresh) {
            warn('Native Intune refresh button (automation-id-refresh) was not found. No page reload fallback was used.');
            showToast('The groups were changed, but the Intune refresh button was not found. Click Refresh in the portal manually.', true, 9000);
            return false;
        }

        log('Refreshing the group list only by clicking the native Intune refresh button.');
        refresh.click();
        return true;
    }

    async function removeSelectedGroups() {
        if (busy) return;
        const groups = [...selectedGroups.values()];
        if (groups.length === 0) return;

        const shown = groups.slice(0, 15).map(group => `• ${group.name}`);
        if (groups.length > shown.length) shown.push(`• … und ${groups.length - shown.length} weitere`);

        const confirmed = window.confirm(
            `Really remove the device from ${groups.length} group${groups.length === 1 ? '' : 's'}?\n\n${shown.join('\n')}\n\nOnly directly assigned memberships are processed.`
        );
        if (!confirmed) {
            log('Removal canceled by the user.');
            return;
        }

        log(`Removal confirmed. Processing ${groups.length} group(s).`);
        setUiBusy(true);
        const results = [];

        try {
            requestContext();
            scanMsalSessionStorageAccessTokens(true);
            scanStorageForGraphTokens(true);
            log('Resolving the device object for the Graph DELETE ...');
            const device = await resolveDeviceObject();
            log('Resolved Entra device:', device);

            for (let index = 0; index < groups.length; index++) {
                const group = groups[index];
                const button = document.getElementById('tm-dgm-remove-button');
                const label = button && (button.querySelector('.ms-Button-label') || button.querySelector('[data-tm-dgm-label]'));
                if (label) label.textContent = `Remove (${index + 1}/${groups.length})…`;

                try {
                    await deleteMembership(group.groupId, device.objectId);
                    results.push({ ...group, success: true });
                    selectedGroups.delete(group.groupId);
                    log(`Removed from group ${group.name} (${group.groupId}).`);
                } catch (error) {
                    results.push({ ...group, success: false, error });
                    warn(`Failed for group ${group.name} (${group.groupId}):`, error);
                }
            }

            const successes = results.filter(result => result.success);
            const failures = results.filter(result => !result.success);

            if (successes.length > 0) {
                showToast(`${device.displayName}: removed ${successes.length} group membership${successes.length === 1 ? '' : 's'}.`);
            }

            if (failures.length > 0) {
                const details = failures
                    .slice(0, 10)
                    .map(result => `• ${result.name}: ${formatError(result.error)}`)
                    .join('\n');
                showToast(`${failures.length} group${failures.length === 1 ? '' : 's'} could not be removed:\n${details}`, true, 12000);
            }

            // Never reload the page directly. Refresh the membership list only
            // through the native Intune command observed in this blade:
            // button.automation-id-refresh
            if (successes.length > 0) {
                schedulePortalRefreshAfterMembershipChange('Remove');
            }
        } finally {
            setUiBusy(false);
            queueRender();
        }
    }

    function initializeFrameUi() {
        document.documentElement.dataset.tmDgmMultiRemove = 'active';
        addStyle();
        startObserver();
        requestContext();

        contextTimer = window.setInterval(() => {
            requestContext();
            scanMsalSessionStorageAccessTokens();
            scanStorageForGraphTokens();
        }, 2000);

        window.setTimeout(() => {
            requestContext();
            if (!frameIdentityLogged) {
                log('No parent-frame identity received yet.');
            }
        }, 1200);

        log('ReactBlade DOM watcher active. Waiting for parent-frame identity and group grid.');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeFrameUi, { once: true });
    } else {
        initializeFrameUi();
    }
})();
