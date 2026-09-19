// ==UserScript==
// @name         Entra Group Members - Host List Graph Add/Remove
// @namespace    xento.betterintuneui
// @version      18.0.0
// @description  Add or remove Entra device group members from a pasted hostname list by using the existing Microsoft Graph session.
// @author       Xento
// @match        https://reactblade.portal.azure.net/*
// @match        https://*.reactblade.portal.azure.net/*
// @match        https://reactblade-ms.portal.azure.net/*
// @match        https://*.reactblade-ms.portal.azure.net/*
// @match        https://reactblade-rc.portal.azure.net/*
// @match        https://*.reactblade-rc.portal.azure.net/*
// @grant        unsafeWindow
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    const PAGE = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
    const VERSION = '18.0.0';
    const SCRIPT_ID = 'tm-entra-group-member-hostlist-v18';
    const PANEL_ID = SCRIPT_ID + '-panel';
    const NATIVE_MENU_ITEM_CLASS = SCRIPT_ID + '-native-menu-item';

    const CFG = {
        graphContextWaitMs: 5000,
        resolveBatchSize: 20,
        mutationBatchSize: 20,
        graphMaxRetries: 3,
        graphDefaultRetryMs: 2000,
        maxNextLinkPages: 20,
        menuRetryDelays: [0, 25, 75, 150, 300, 600, 1000, 1600]
    };

    let graphAuthorization = null;
    let currentGroupId = null;
    let currentGroupInfo = null;
    let running = false;
    let cancelRequested = false;
    let ui = null;
    let preparedAction = null;
    let bulkButtonBound = false;

    function now() {
        return Date.now();
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function normalize(value) {
        return String(value ?? '').trim().toLowerCase();
    }

    function looksLikeGuid(value) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
            .test(String(value || '').trim());
    }

    function chunkArray(items, size) {
        const chunks = [];
        for (let i = 0; i < items.length; i += size) {
            chunks.push(items.slice(i, i + size));
        }
        return chunks;
    }

    function parseHostnames(text) {
        const values = String(text || '')
            .split(/[\r\n\t,; ]+/)
            .map(value => value.trim())
            .filter(Boolean);

        const result = [];
        const seen = new Set();

        for (const value of values) {
            const key = normalize(value);
            if (seen.has(key)) continue;
            seen.add(key);
            result.push(value);
        }

        return result;
    }

    function escapeODataString(value) {
        return String(value || '').replace(/'/g, "''");
    }

    function isVisibleElement(element) {
        if (!element || !(element instanceof Element)) return false;

        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();

        return style.display !== 'none' &&
               style.visibility !== 'hidden' &&
               rect.width > 0 &&
               rect.height > 0;
    }

    function isGraphUrl(url) {
        try {
            const parsed = new URL(String(url), location.href);
            return parsed.hostname.toLowerCase() === 'graph.microsoft.com';
        } catch {
            return false;
        }
    }

    function getHeaderValue(headers, name) {
        if (!headers) return '';
        const wanted = normalize(name);

        try {
            if (typeof headers.get === 'function') {
                return headers.get(name) || headers.get(wanted) || '';
            }
        } catch {}

        if (Array.isArray(headers)) {
            const pair = headers.find(entry =>
                Array.isArray(entry) && normalize(entry[0]) === wanted
            );
            return pair ? String(pair[1] || '') : '';
        }

        if (typeof headers === 'object') {
            for (const [key, value] of Object.entries(headers)) {
                if (normalize(key) === wanted) return String(value || '');
            }
        }

        return '';
    }

    function extractGroupIdFromText(value) {
        let text = String(value || '');
        if (!text) return null;

        try {
            text = decodeURIComponent(text);
        } catch {}

        text = text.replace(/\\\//g, '/');

        const guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
        const memberMatch = text.match(
            new RegExp('groups/(' + guid + ')/(?:members|transitiveMembers)', 'i')
        );

        return memberMatch ? memberMatch[1].toLowerCase() : null;
    }

    function captureGraphContext(url, body, headers) {
        if (!isGraphUrl(url)) return;

        const authorization = getHeaderValue(headers, 'Authorization');
        if (/^Bearer\s+\S+/i.test(authorization)) {
            graphAuthorization = authorization;
        }

        const groupId =
            extractGroupIdFromText(url) ||
            extractGroupIdFromText(body);

        if (groupId && currentGroupId !== groupId) {
            currentGroupId = groupId;
            currentGroupInfo = null;
            preparedAction = null;
        }
    }

    function installNetworkHooks() {
        try {
            const originalFetch = PAGE.fetch;

            if (typeof originalFetch === 'function' && !originalFetch.__tmHostlistV18Wrapped) {
                const wrappedFetch = async function (...args) {
                    const request = args[0];
                    const init = args[1] || {};

                    const url =
                        typeof request === 'string' || request instanceof URL
                            ? String(request)
                            : request?.url || '';

                    if (isGraphUrl(url)) {
                        const body =
                            init.body !== undefined
                                ? init.body
                                : request?.body || '';

                        const headers =
                            init.headers ||
                            request?.headers ||
                            null;

                        captureGraphContext(url, body, headers);
                    }

                    return originalFetch.apply(this, args);
                };

                Object.defineProperty(wrappedFetch, '__tmHostlistV18Wrapped', {
                    value: true
                });

                PAGE.fetch = wrappedFetch;
            }
        } catch (error) {
            console.warn('[Entra Host List v18] Could not hook fetch():', error);
        }

        try {
            const XHR = PAGE.XMLHttpRequest;

            if (XHR && !XHR.prototype.__tmHostlistV18Wrapped) {
                const originalOpen = XHR.prototype.open;
                const originalSend = XHR.prototype.send;
                const originalSetRequestHeader = XHR.prototype.setRequestHeader;

                XHR.prototype.open = function (method, url, ...rest) {
                    this.__tmHostlistV18Url = String(url || '');
                    this.__tmHostlistV18Headers = {};
                    return originalOpen.call(this, method, url, ...rest);
                };

                XHR.prototype.setRequestHeader = function (name, value) {
                    this.__tmHostlistV18Headers ||= {};
                    this.__tmHostlistV18Headers[name] = value;
                    return originalSetRequestHeader.call(this, name, value);
                };

                XHR.prototype.send = function (body) {
                    const url = this.__tmHostlistV18Url || '';

                    if (isGraphUrl(url)) {
                        captureGraphContext(
                            url,
                            body,
                            this.__tmHostlistV18Headers || {}
                        );
                    }

                    return originalSend.call(this, body);
                };

                Object.defineProperty(XHR.prototype, '__tmHostlistV18Wrapped', {
                    value: true
                });
            }
        } catch (error) {
            console.warn('[Entra Host List v18] Could not hook XMLHttpRequest:', error);
        }
    }

    installNetworkHooks();

    async function waitForGraphContext(timeoutMs = CFG.graphContextWaitMs) {
        const started = now();

        while (now() - started < timeoutMs) {
            if (graphAuthorization && currentGroupId) {
                return { hasToken: true, groupId: currentGroupId };
            }
            await sleep(100);
        }

        return {
            hasToken: !!graphAuthorization,
            groupId: currentGroupId
        };
    }

    function graphHeaders(extra = {}) {
        if (!graphAuthorization) {
            throw new Error(
                'The Microsoft Graph access token has not been detected from the current portal session yet.'
            );
        }

        return {
            'Accept': 'application/json',
            'Authorization': graphAuthorization,
            ...extra
        };
    }

    async function graphFetch(url, options = {}) {
        const headers = {
            ...graphHeaders(),
            ...(options.headers || {})
        };

        return PAGE.fetch(url, {
            ...options,
            headers
        });
    }

    async function fetchCurrentGroupInfo(force = false) {
        if (!currentGroupId || !graphAuthorization) return null;
        if (!force && currentGroupInfo?.id === currentGroupId) return currentGroupInfo;

        const response = await graphFetch(
            `https://graph.microsoft.com/v1.0/groups/${currentGroupId}` +
            '?$select=id,displayName,groupTypes,membershipRule,' +
            'membershipRuleProcessingState,mailEnabled,securityEnabled,isAssignableToRole',
            { method: 'GET' }
        );

        if (!response.ok) {
            throw new Error(
                `Could not read the current group information: HTTP ${response.status}`
            );
        }

        currentGroupInfo = await response.json();
        return currentGroupInfo;
    }

    function validateGroupForDeviceMutation(group) {
        if (!group) {
            throw new Error('The current group could not be determined.');
        }

        const groupTypes = (group.groupTypes || []).map(normalize);

        if (groupTypes.includes('dynamicmembership')) {
            throw new Error(
                `The group "${group.displayName || currentGroupId}" uses dynamic membership. ` +
                'Devices cannot be added or removed manually.'
            );
        }

        if (groupTypes.includes('unified')) {
            throw new Error(
                `The group "${group.displayName || currentGroupId}" is a Microsoft 365 group. ` +
                'Device membership is not supported for this group type.'
            );
        }

        if (group.mailEnabled && !groupTypes.includes('unified')) {
            throw new Error(
                `The group "${group.displayName || currentGroupId}" is mail-enabled and cannot be ` +
                'managed as a standard device security group through this workflow.'
            );
        }

        if (group.securityEnabled !== true) {
            throw new Error(
                `The group "${group.displayName || currentGroupId}" is not a supported security group.`
            );
        }
    }

    function retryAfterMs(headers, fallbackMs = CFG.graphDefaultRetryMs) {
        if (!headers) return fallbackMs;

        let raw = '';

        try {
            if (typeof headers.get === 'function') {
                raw = headers.get('Retry-After') || '';
            } else if (typeof headers === 'object') {
                for (const [key, value] of Object.entries(headers)) {
                    if (normalize(key) === 'retry-after') {
                        raw = String(value || '');
                        break;
                    }
                }
            }
        } catch {}

        const seconds = Number(raw);
        if (Number.isFinite(seconds) && seconds > 0) {
            return Math.min(30000, Math.max(500, seconds * 1000));
        }

        return fallbackMs;
    }

    async function sendGraphBatch(requests) {
        const response = await graphFetch(
            'https://graph.microsoft.com/v1.0/$batch',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ requests })
            }
        );

        if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(
                `Microsoft Graph batch request failed: HTTP ${response.status}` +
                (text ? ` - ${text.slice(0, 300)}` : '')
            );
        }

        return response.json();
    }

    function buildExactDeviceQuery(hostname, mode) {
        const filter = `displayName eq '${escapeODataString(hostname)}'`;
        const encodedFilter = encodeURIComponent(filter);
        const select = 'id,displayName,deviceId,operatingSystem';

        if (mode === 'remove') {
            return `/groups/${currentGroupId}/members/microsoft.graph.device` +
                `?$select=${select}` +
                `&$filter=${encodedFilter}` +
                '&$count=true&$top=100';
        }

        return `/devices` +
            `?$select=${select}` +
            `&$filter=${encodedFilter}` +
            '&$count=true&$top=100';
    }

    function exactDevicesFromValue(value, hostname) {
        const wanted = normalize(hostname);
        const byId = new Map();

        for (const device of Array.isArray(value) ? value : []) {
            if (normalize(device?.displayName) !== wanted) continue;
            if (!looksLikeGuid(device?.id)) continue;

            byId.set(normalize(device.id), {
                id: String(device.id),
                displayName: String(device.displayName || hostname),
                deviceId: String(device.deviceId || ''),
                operatingSystem: String(device.operatingSystem || '')
            });
        }

        return [...byId.values()];
    }

    async function followNextLinks(firstBody, hostname) {
        const collected = new Map();

        for (const device of exactDevicesFromValue(firstBody?.value, hostname)) {
            collected.set(normalize(device.id), device);
        }

        let nextLink = firstBody?.['@odata.nextLink'] || '';
        let page = 0;

        while (nextLink && page++ < CFG.maxNextLinkPages) {
            if (cancelRequested) throw new Error('Operation cancelled.');

            const response = await graphFetch(nextLink, {
                method: 'GET',
                headers: {
                    'ConsistencyLevel': 'eventual'
                }
            });

            if (!response.ok) {
                throw new Error(
                    `${hostname}: Could not load the next result page: HTTP ${response.status}`
                );
            }

            const body = await response.json();

            for (const device of exactDevicesFromValue(body?.value, hostname)) {
                collected.set(normalize(device.id), device);
            }

            nextLink = body?.['@odata.nextLink'] || '';
        }

        return [...collected.values()];
    }

    async function resolveHostChunk(hosts, mode) {
        let pending = hosts.map(hostname => ({ hostname }));
        const resolved = new Map();
        const errors = new Map();

        for (let attempt = 1; attempt <= CFG.graphMaxRetries && pending.length; attempt++) {
            const idMap = new Map();
            const requests = pending.map((entry, index) => {
                const id = String(index + 1);
                idMap.set(id, entry);

                return {
                    id,
                    method: 'GET',
                    url: buildExactDeviceQuery(entry.hostname, mode),
                    headers: {
                        'ConsistencyLevel': 'eventual'
                    }
                };
            });

            const payload = await sendGraphBatch(requests);
            const retry = [];
            let retryDelay = CFG.graphDefaultRetryMs;
            const seenResponseIds = new Set();

            for (const sub of payload.responses || []) {
                const entry = idMap.get(String(sub.id));
                if (!entry) continue;
                seenResponseIds.add(String(sub.id));

                const status = Number(sub.status || 0);

                if (status === 200) {
                    try {
                        const devices = await followNextLinks(sub.body || {}, entry.hostname);
                        resolved.set(normalize(entry.hostname), devices);
                        errors.delete(normalize(entry.hostname));
                    } catch (error) {
                        errors.set(normalize(entry.hostname), String(error?.message || error));
                    }
                    continue;
                }

                if ([429, 503, 504].includes(status) && attempt < CFG.graphMaxRetries) {
                    retry.push(entry);
                    retryDelay = Math.max(
                        retryDelay,
                        retryAfterMs(sub.headers, CFG.graphDefaultRetryMs)
                    );
                    continue;
                }

                errors.set(
                    normalize(entry.hostname),
                    sub.body?.error?.message || sub.body?.message || `HTTP ${status}`
                );
            }

            for (const [id, entry] of idMap.entries()) {
                if (seenResponseIds.has(id)) continue;

                if (attempt < CFG.graphMaxRetries) {
                    retry.push(entry);
                } else {
                    errors.set(
                        normalize(entry.hostname),
                        'No Microsoft Graph subresponse was returned.'
                    );
                }
            }

            pending = retry;

            if (pending.length) {
                log(
                    `${pending.length} lookup request(s) will be retried after ${retryDelay} ms.`
                );
                await sleep(retryDelay);
            }
        }

        for (const entry of pending) {
            const key = normalize(entry.hostname);
            if (!errors.has(key)) {
                errors.set(key, 'Lookup did not complete after multiple attempts.');
            }
        }

        return { resolved, errors };
    }

    async function resolveHostnames(hosts, mode) {
        const context = await waitForGraphContext();

        if (!context.hasToken || !context.groupId) {
            throw new Error(
                `Microsoft Graph context is incomplete: token=${context.hasToken ? 'detected' : 'not detected'}, ` +
                `group=${context.groupId || 'not detected'}. ` +
                'Let the group members page finish loading and try again.'
            );
        }

        const group = await fetchCurrentGroupInfo();
        validateGroupForDeviceMutation(group);

        const chunks = chunkArray(hosts, CFG.resolveBatchSize);
        const allResolved = new Map();
        const allErrors = new Map();

        for (let index = 0; index < chunks.length; index++) {
            if (cancelRequested) throw new Error('Operation cancelled.');

            ui.status.textContent =
                `Resolving: batch ${index + 1} of ${chunks.length} ` +
                `(${chunks[index].length} hostname(s))`;

            log(
                `Lookup batch ${index + 1}/${chunks.length}: ` +
                `${chunks[index].length} hostname(s) via Microsoft Graph.`
            );

            const result = await resolveHostChunk(chunks[index], mode);

            for (const [key, value] of result.resolved.entries()) {
                allResolved.set(key, value);
            }

            for (const [key, value] of result.errors.entries()) {
                allErrors.set(key, value);
            }
        }

        const foundEntries = [];
        const missingHosts = [];
        const errorEntries = [];
        const itemById = new Map();

        for (const hostname of hosts) {
            const key = normalize(hostname);

            if (allErrors.has(key)) {
                errorEntries.push({
                    hostname,
                    error: allErrors.get(key)
                });
                continue;
            }

            const devices = allResolved.get(key) || [];

            if (!devices.length) {
                missingHosts.push(hostname);
                continue;
            }

            foundEntries.push({ hostname, devices });

            for (const device of devices) {
                const idKey = normalize(device.id);
                if (itemById.has(idKey)) continue;

                itemById.set(idKey, {
                    hostname,
                    id: device.id,
                    deviceId: device.deviceId,
                    operatingSystem: device.operatingSystem
                });
            }
        }

        return {
            mode,
            group,
            items: [...itemById.values()],
            foundEntries,
            missingHosts,
            errorEntries,
            preparedAt: new Date()
        };
    }

    function isAlreadyMemberError(message) {
        const text = normalize(message);
        return text.includes('already exist') ||
               text.includes('already a member') ||
               text.includes('object references already exist') ||
               text.includes('added object references already exist');
    }

    function looksLikeReplicationError(message) {
        const text = normalize(message);
        return text.includes("doesn't exist") ||
               text.includes('does not exist') ||
               text.includes('cannot be found') ||
               text.includes('not found');
    }

    async function sendMutationChunk(items, mode) {
        let pending = [...items];
        const finished = [];

        for (let attempt = 1; attempt <= CFG.graphMaxRetries && pending.length; attempt++) {
            const idMap = new Map();

            const requests = pending.map((item, index) => {
                const id = String(index + 1);
                idMap.set(id, item);

                if (mode === 'add') {
                    return {
                        id,
                        method: 'POST',
                        url: `/groups/${currentGroupId}/members/$ref`,
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: {
                            '@odata.id':
                                `https://graph.microsoft.com/v1.0/directoryObjects/${item.id}`
                        }
                    };
                }

                return {
                    id,
                    method: 'DELETE',
                    url: `/groups/${currentGroupId}/members/${item.id}/$ref`
                };
            });

            const payload = await sendGraphBatch(requests);
            const retry = [];
            let retryDelay = CFG.graphDefaultRetryMs;
            const seenResponseIds = new Set();

            for (const sub of payload.responses || []) {
                const item = idMap.get(String(sub.id));
                if (!item) continue;
                seenResponseIds.add(String(sub.id));

                const status = Number(sub.status || 0);
                const message =
                    sub.body?.error?.message ||
                    sub.body?.message ||
                    '';

                if (status === 204) {
                    finished.push({
                        ...item,
                        status,
                        result: mode === 'add' ? 'added' : 'removed'
                    });
                    continue;
                }

                if (mode === 'remove' && status === 404) {
                    finished.push({
                        ...item,
                        status,
                        result: 'already-absent'
                    });
                    continue;
                }

                if (mode === 'add' && status === 400 && isAlreadyMemberError(message)) {
                    finished.push({
                        ...item,
                        status,
                        result: 'already-member'
                    });
                    continue;
                }

                const transient =
                    [429, 503, 504].includes(status) ||
                    (mode === 'add' && status === 400 && looksLikeReplicationError(message));

                if (transient && attempt < CFG.graphMaxRetries) {
                    retry.push(item);
                    retryDelay = Math.max(
                        retryDelay,
                        retryAfterMs(sub.headers, CFG.graphDefaultRetryMs)
                    );
                    continue;
                }

                finished.push({
                    ...item,
                    status,
                    result: 'failed',
                    error: message || `HTTP ${status}`
                });
            }

            for (const [id, item] of idMap.entries()) {
                if (seenResponseIds.has(id)) continue;

                if (attempt < CFG.graphMaxRetries) {
                    retry.push(item);
                } else {
                    finished.push({
                        ...item,
                        status: 0,
                        result: 'failed',
                        error: 'No Microsoft Graph subresponse was returned.'
                    });
                }
            }

            pending = retry;

            if (pending.length) {
                log(
                    `${pending.length} ${mode === 'add' ? 'add' : 'remove'} request(s) ` +
                    `will be retried after ${retryDelay} ms.`
                );
                await sleep(retryDelay);
            }
        }

        for (const item of pending) {
            finished.push({
                ...item,
                status: 0,
                result: 'failed',
                error: 'Request did not complete after multiple attempts.'
            });
        }

        return finished;
    }

    async function executePreparedAction() {
        if (!preparedAction?.items?.length) {
            throw new Error('No device list has been prepared yet.');
        }

        const context = await waitForGraphContext();
        if (!context.hasToken || !context.groupId) {
            throw new Error('The Microsoft Graph token or group ID is no longer available.');
        }

        const group = await fetchCurrentGroupInfo(true);
        validateGroupForDeviceMutation(group);

        const mode = preparedAction.mode;
        const chunks = chunkArray(preparedAction.items, CFG.mutationBatchSize);
        const results = [];

        for (let index = 0; index < chunks.length; index++) {
            if (cancelRequested) throw new Error('Operation cancelled.');

            ui.status.textContent =
                `${mode === 'add' ? 'Adding' : 'Removing'}: ` +
                `batch ${index + 1} of ${chunks.length} ` +
                `(${chunks[index].length} device(s))`;

            log(
                `${mode === 'add' ? 'Add' : 'Remove'} batch ` +
                `${index + 1}/${chunks.length} is being sent ` +
                `(${chunks[index].length} device(s)).`
            );

            results.push(...await sendMutationChunk(chunks[index], mode));
        }

        return { group, mode, results };
    }

    function scrollLogToBottom() {
        if (!ui?.log) return;

        requestAnimationFrame(() => {
            if (!ui?.log) return;
            ui.log.scrollTop = ui.log.scrollHeight;
        });
    }

    function log(message) {
        if (!ui?.log) return;

        const line = document.createElement('div');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        ui.log.appendChild(line);
        scrollLogToBottom();
    }

    function getBulkOperationsButton() {
        return document.querySelector('button[data-testid="bulkOperations"]');
    }

    function closeNativeBulkMenu() {
        const bulkButton = getBulkOperationsButton();

        if (bulkButton?.getAttribute('aria-expanded') === 'true') {
            try {
                bulkButton.click();
                return;
            } catch {}
        }

        try {
            document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', {
                key: 'Escape',
                code: 'Escape',
                keyCode: 27,
                which: 27,
                bubbles: true
            }));
        } catch {}
    }

    function refreshNativeMemberList() {
        const refresh = document.querySelector('button[data-testid="RefreshCmdBtn"]');
        if (!refresh || !isVisibleElement(refresh)) return false;

        setTimeout(() => {
            try {
                refresh.click();
            } catch {}
        }, 250);

        return true;
    }

    function requestHostlistAdd() {
        closeNativeBulkMenu();
        setTimeout(() => createPanel('add'), 0);
    }

    function requestHostlistRemove() {
        closeNativeBulkMenu();
        setTimeout(() => createPanel('remove'), 0);
    }

    function cleanClonedMenuNode(root) {
        if (!(root instanceof Element)) return;

        for (const element of [root, ...root.querySelectorAll('*')]) {
            element.removeAttribute('id');
            element.removeAttribute('elementtiming');
            element.removeAttribute('aria-controls');
            element.removeAttribute('aria-describedby');
            element.removeAttribute('aria-labelledby');
            element.removeAttribute('data-focuszone-id');
        }
    }

    function createNativeHostlistMenuItem(sourceButton, mode, label) {
        if (!sourceButton) return null;

        const sourceLi = sourceButton.closest('li[role="presentation"]');
        if (!sourceLi) return null;

        const li = sourceLi.cloneNode(true);
        cleanClonedMenuNode(li);

        const button = li.querySelector('button[role="menuitem"]');
        if (!button) return null;

        li.classList.add(NATIVE_MENU_ITEM_CLASS);
        li.dataset.tmHostlistMode = mode;

        button.classList.add(NATIVE_MENU_ITEM_CLASS);
        button.dataset.tmHostlistMode = mode;
        button.dataset.testid =
            mode === 'add'
                ? 'tmHostlistAddMembers'
                : 'tmHostlistRemoveMembers';

        button.setAttribute(
            'name',
            mode === 'add'
                ? 'Add devices from host list'
                : 'Remove devices from host list'
        );
        button.setAttribute(
            'data-telemetryname',
            mode === 'add'
                ? 'Tampermonkey - Add devices from host list'
                : 'Tampermonkey - Remove devices from host list'
        );
        button.setAttribute('aria-disabled', 'false');
        button.removeAttribute('disabled');
        button.setAttribute('tabindex', '-1');

        const labelElement =
            button.querySelector('.ms-ContextualMenu-itemText') ||
            button.querySelector('span');

        if (labelElement) {
            labelElement.textContent = label;
        }

        button.addEventListener('click', event => {
            event.preventDefault();

            if (mode === 'add') {
                requestHostlistAdd();
            } else {
                requestHostlistRemove();
            }
        });

        return li;
    }

    function updateNativeMenuAria(list) {
        const buttons = [
            ...list.querySelectorAll(
                ':scope > li[role="presentation"] > button[role="menuitem"]'
            )
        ];

        const size = buttons.length;

        buttons.forEach((button, index) => {
            button.setAttribute('aria-posinset', String(index + 1));
            button.setAttribute('aria-setsize', String(size));
        });
    }

    function findBulkMenuParts() {
        const bulkButton = getBulkOperationsButton();
        if (!bulkButton) return null;

        const controlsId = bulkButton.getAttribute('aria-controls');
        const controlledMenu = controlsId
            ? document.getElementById(controlsId)
            : null;

        const menu =
            controlledMenu ||
            document.querySelector(
                '.ms-ContextualMenu-container[role="menu"] ' +
                'button[data-testid="bulkGroupImportMember"]'
            )?.closest('.ms-ContextualMenu-container[role="menu"]');

        if (!menu || !isVisibleElement(menu)) return null;

        const list =
            menu.querySelector('ul.ms-ContextualMenu-list') ||
            menu.querySelector('ul[role="presentation"]');

        if (!list) return null;

        return {
            menu,
            list,
            importButton: menu.querySelector(
                'button[data-testid="bulkGroupImportMember"][role="menuitem"]'
            ),
            removeButton: menu.querySelector(
                'button[data-testid="bulkGroupRemoveMember"][role="menuitem"]'
            ),
            downloadButton: menu.querySelector(
                'button[data-testid="bulkGroupDownloadMembers"][role="menuitem"]'
            )
        };
    }

    function injectIntoNativeBulkMenu() {
        const parts = findBulkMenuParts();
        if (!parts) return false;

        const { list, importButton, removeButton } = parts;
        if (!importButton && !removeButton) return false;

        if (!list.querySelector(
            `.${NATIVE_MENU_ITEM_CLASS}[data-tm-hostlist-mode="add"]`
        )) {
            const addItem = createNativeHostlistMenuItem(
                importButton || removeButton,
                'add',
                'Add devices from host list'
            );

            if (addItem) {
                const importLi = importButton?.closest('li[role="presentation"]');
                if (importLi?.parentElement === list) {
                    importLi.insertAdjacentElement('afterend', addItem);
                } else {
                    list.appendChild(addItem);
                }
            }
        }

        if (!list.querySelector(
            `.${NATIVE_MENU_ITEM_CLASS}[data-tm-hostlist-mode="remove"]`
        )) {
            const removeItem = createNativeHostlistMenuItem(
                removeButton || importButton,
                'remove',
                'Remove devices from host list'
            );

            if (removeItem) {
                const nativeRemoveLi = removeButton?.closest('li[role="presentation"]');
                if (nativeRemoveLi?.parentElement === list) {
                    nativeRemoveLi.insertAdjacentElement('afterend', removeItem);
                } else {
                    list.appendChild(removeItem);
                }
            }
        }

        updateNativeMenuAria(list);

        const success =
            !!list.querySelector(
                `.${NATIVE_MENU_ITEM_CLASS}[data-tm-hostlist-mode="add"]`
            ) &&
            !!list.querySelector(
                `.${NATIVE_MENU_ITEM_CLASS}[data-tm-hostlist-mode="remove"]`
            );

        if (success && !list.dataset.tmHostlistV18Logged) {
            list.dataset.tmHostlistV18Logged = '1';
            console.info(
                '[Entra Host List v18] Host list actions were added to Bulk operations.'
            );
        }

        return success;
    }

    function scheduleMenuInjection() {
        console.info('[Entra Host List v18] Bulk operations opened.');
        for (const delay of CFG.menuRetryDelays) {
            setTimeout(injectIntoNativeBulkMenu, delay);
        }
    }

    function bindBulkOperationsButton() {
        const button = getBulkOperationsButton();
        if (!button) return false;

        if (!button.dataset.tmHostlistV18Bound) {
            button.dataset.tmHostlistV18Bound = '1';
            button.addEventListener('click', scheduleMenuInjection, true);
            button.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ' || event.key === 'ArrowDown') {
                    scheduleMenuInjection();
                }
            }, true);

            console.info('[Entra Host List v18] Bulk operations button detected.');
        }

        if (button.getAttribute('aria-expanded') === 'true') {
            injectIntoNativeBulkMenu();
        }

        bulkButtonBound = true;
        return true;
    }

    function renderPreview(prepared) {
        if (!ui?.preview) return;

        const mode = prepared.mode;
        ui.preview.replaceChildren();
        ui.preview.style.display = '';

        const groupLine = document.createElement('div');
        groupLine.style.cssText = [
            'padding:7px 8px',
            'font-weight:700',
            'border-bottom:1px solid var(--colorContainerBorderSecondary, #edebe9)'
        ].join(';');
        groupLine.textContent =
            `Group: ${prepared.group?.displayName || currentGroupId} (${currentGroupId})`;
        ui.preview.appendChild(groupLine);

        const header = document.createElement('div');
        header.style.cssText = [
            'display:grid',
            'grid-template-columns:120px 1fr 110px',
            'gap:8px',
            'padding:6px 8px',
            'font-weight:700',
            'background:var(--colorContainerBackgroundSecondary, #f3f2f1)',
            'position:sticky',
            'top:0',
            'z-index:1'
        ].join(';');
        header.innerHTML = '<span>Hostname</span><span>Object ID</span><span>Status</span>';
        ui.preview.appendChild(header);

        for (const entry of prepared.foundEntries) {
            for (const device of entry.devices) {
                const row = document.createElement('div');
                row.style.cssText = [
                    'display:grid',
                    'grid-template-columns:120px 1fr 110px',
                    'gap:8px',
                    'padding:5px 8px',
                    'border-top:1px solid var(--colorContainerBorderPrimary, #f3f2f1)'
                ].join(';');

                const host = document.createElement('span');
                host.textContent = entry.hostname;

                const id = document.createElement('span');
                id.textContent = device.id;
                id.style.overflowWrap = 'anywhere';

                const status = document.createElement('span');
                status.textContent = mode === 'add' ? 'Found' : 'Member';
                status.style.fontWeight = '700';

                row.append(host, id, status);
                ui.preview.appendChild(row);
            }
        }

        for (const hostname of prepared.missingHosts) {
            const row = document.createElement('div');
            row.style.cssText = [
                'display:grid',
                'grid-template-columns:120px 1fr 110px',
                'gap:8px',
                'padding:5px 8px',
                'border-top:1px solid var(--colorContainerBorderPrimary, #f3f2f1)'
            ].join(';');

            const host = document.createElement('span');
            host.textContent = hostname;

            const id = document.createElement('span');
            id.textContent = '-';

            const status = document.createElement('span');
            status.textContent = mode === 'remove' ? 'Not a member' : 'Not found';
            status.style.fontWeight = '700';

            row.append(host, id, status);
            ui.preview.appendChild(row);
        }

        for (const entry of prepared.errorEntries) {
            const row = document.createElement('div');
            row.style.cssText = [
                'display:grid',
                'grid-template-columns:120px 1fr 110px',
                'gap:8px',
                'padding:5px 8px',
                'border-top:1px solid var(--colorContainerBorderPrimary, #f3f2f1)'
            ].join(';');

            const host = document.createElement('span');
            host.textContent = entry.hostname;

            const message = document.createElement('span');
            message.textContent = entry.error;
            message.style.overflowWrap = 'anywhere';

            const status = document.createElement('span');
            status.textContent = 'ERROR';
            status.style.fontWeight = '700';

            row.append(host, message, status);
            ui.preview.appendChild(row);
        }
    }

    async function prepareMode(hosts, mode) {
        preparedAction = null;
        ui.execute.style.display = 'none';
        ui.execute.disabled = true;
        ui.preview.style.display = 'none';
        ui.preview.replaceChildren();

        log(
            `${hosts.length} hostname(s) will be resolved directly through Microsoft Graph ` +
            `(${mode === 'add' ? 'tenant devices' : 'direct device members of the current group'}).`
        );

        const prepared = await resolveHostnames(hosts, mode);
        preparedAction = prepared;
        renderPreview(prepared);

        for (const entry of prepared.foundEntries) {
            log(
                `${entry.hostname}: ${entry.devices.length} exact device object(s) found.`
            );
        }

        for (const hostname of prepared.missingHosts) {
            log(
                `${hostname}: ${mode === 'remove' ? 'no direct device member' : 'no device'} ` +
                'with this exact display name was found.'
            );
        }

        for (const entry of prepared.errorEntries) {
            log(`${entry.hostname}: Lookup failed: ${entry.error}`);
        }

        const count = prepared.items.length;

        ui.status.textContent =
            `${count} device(s) prepared; ` +
            `${prepared.missingHosts.length} not found; ` +
            `${prepared.errorEntries.length} error(s)`;

        if (!count) {
            log('No devices were prepared for this action.');
            return;
        }

        ui.execute.textContent =
            `${mode === 'add' ? 'Add' : 'Remove'} ${count} ` +
            `device${count === 1 ? '' : 's'}`;
        ui.execute.style.display = '';
        ui.execute.disabled = false;

        log(
            `Preview created. The separate "${ui.execute.textContent}" button ` +
            'will apply the group membership change.'
        );
    }

    async function executeMode() {
        if (!preparedAction?.items?.length) return;

        const result = await executePreparedAction();
        const failed = result.results.filter(entry => entry.result === 'failed');

        if (result.mode === 'add') {
            const added = result.results.filter(entry => entry.result === 'added');
            const already = result.results.filter(entry => entry.result === 'already-member');

            for (const entry of result.results) {
                if (entry.result === 'added') {
                    log(`${entry.hostname}: added to the group (${entry.id}).`);
                } else if (entry.result === 'already-member') {
                    log(`${entry.hostname}: already a member (${entry.id}).`);
                } else {
                    log(
                        `${entry.hostname}: add failed (${entry.id}), ` +
                        `${entry.error || 'HTTP ' + entry.status}.`
                    );
                }
            }

            ui.status.textContent =
                `Added: ${added.length}; already a member: ${already.length}; ` +
                `errors: ${failed.length}`;

            log(
                `Add completed. Added=${added.length}; ` +
                `already a member=${already.length}; errors=${failed.length}.`
            );
        } else {
            const removed = result.results.filter(entry => entry.result === 'removed');
            const absent = result.results.filter(entry => entry.result === 'already-absent');

            for (const entry of result.results) {
                if (entry.result === 'removed') {
                    log(`${entry.hostname}: removed from the group (${entry.id}).`);
                } else if (entry.result === 'already-absent') {
                    log(`${entry.hostname}: membership was already absent (${entry.id}).`);
                } else {
                    log(
                        `${entry.hostname}: remove failed (${entry.id}), ` +
                        `${entry.error || 'HTTP ' + entry.status}.`
                    );
                }
            }

            ui.status.textContent =
                `Removed: ${removed.length}; already absent: ${absent.length}; ` +
                `errors: ${failed.length}`;

            log(
                `Remove completed. Removed=${removed.length}; ` +
                `already absent=${absent.length}; errors=${failed.length}.`
            );
        }

        const failedIds = new Set(failed.map(entry => normalize(entry.id)));
        preparedAction.items = preparedAction.items.filter(item =>
            failedIds.has(normalize(item.id))
        );

        if (preparedAction.items.length) {
            ui.execute.textContent =
                `${preparedAction.mode === 'add' ? 'Retry adding' : 'Retry removing'} ` +
                `${preparedAction.items.length} failed device` +
                `${preparedAction.items.length === 1 ? '' : 's'}`;
            ui.execute.disabled = false;
            ui.execute.style.display = '';
        } else {
            ui.execute.style.display = 'none';
        }

        const changed = result.results.some(entry =>
            entry.result === 'added' || entry.result === 'removed'
        );

        if (changed && refreshNativeMemberList()) {
            log('Refreshing the native group members list.');
        }
    }

    function centerPanel(panel) {
        panel.style.top = '50%';
        panel.style.left = '50%';
        panel.style.right = 'auto';
        panel.style.transform = 'translate(-50%, -50%)';
    }

    function createPanel(mode) {
        if (!['add', 'remove'].includes(mode)) return;

        const existing = document.getElementById(PANEL_ID);

        if (existing) {
            if (ui?.mode === mode) {
                existing.style.display = '';
                centerPanel(existing);
                ui.textarea.focus();
                return;
            }

            if (running) cancelRequested = true;
            existing.remove();
            ui = null;
            preparedAction = null;
        }

        const panel = document.createElement('div');
        panel.id = PANEL_ID;
        panel.style.cssText = [
            'position:fixed',
            'top:50%',
            'left:50%',
            'transform:translate(-50%, -50%)',
            'width:500px',
            'max-width:calc(100vw - 40px)',
            'max-height:calc(100vh - 40px)',
            'z-index:2147483647',
            'background:var(--colorContainerBackgroundPrimary, #fff)',
            'color:var(--colorTextPrimary, #242424)',
            'border:1px solid var(--colorContainerBorderSecondary, #c8c6c4)',
            'border-radius:4px',
            'box-shadow:0 8px 30px rgba(0,0,0,.32)',
            'font:13px "Segoe UI",sans-serif'
        ].join(';');

        const header = document.createElement('div');
        header.style.cssText = [
            'display:flex',
            'align-items:center',
            'justify-content:space-between',
            'padding:10px 12px',
            'border-bottom:1px solid var(--colorContainerBorderSecondary, #edebe9)',
            'font-weight:600',
            'cursor:move',
            'user-select:none',
            'touch-action:none'
        ].join(';');

        header.appendChild(document.createTextNode(
            mode === 'add'
                ? 'Add devices from host list'
                : 'Remove devices from host list'
        ));

        const close = document.createElement('button');
        close.type = 'button';
        close.textContent = '×';
        close.title = 'Close';
        close.setAttribute('aria-label', 'Close');
        close.style.cssText =
            'border:0;background:transparent;font-size:22px;cursor:pointer;color:inherit;';
        close.onclick = () => {
            if (running) cancelRequested = true;
            panel.style.display = 'none';
        };
        header.appendChild(close);

        let dragState = null;

        header.addEventListener('pointerdown', event => {
            if (event.button !== 0 || event.target.closest('button')) return;

            const rect = panel.getBoundingClientRect();
            panel.style.left = `${rect.left}px`;
            panel.style.top = `${rect.top}px`;
            panel.style.right = 'auto';
            panel.style.transform = 'none';

            dragState = {
                pointerId: event.pointerId,
                startX: event.clientX,
                startY: event.clientY,
                left: rect.left,
                top: rect.top
            };

            header.setPointerCapture?.(event.pointerId);
            event.preventDefault();
        });

        header.addEventListener('pointermove', event => {
            if (!dragState || dragState.pointerId !== event.pointerId) return;

            const maxLeft = Math.max(0, window.innerWidth - panel.offsetWidth);
            const maxTop = Math.max(0, window.innerHeight - 40);

            panel.style.left = `${Math.min(
                maxLeft,
                Math.max(0, dragState.left + event.clientX - dragState.startX)
            )}px`;

            panel.style.top = `${Math.min(
                maxTop,
                Math.max(0, dragState.top + event.clientY - dragState.startY)
            )}px`;
        });

        const stopDrag = event => {
            if (!dragState || dragState.pointerId !== event.pointerId) return;
            header.releasePointerCapture?.(event.pointerId);
            dragState = null;
        };

        header.addEventListener('pointerup', stopDrag);
        header.addEventListener('pointercancel', stopDrag);

        const body = document.createElement('div');
        body.style.cssText = 'padding:12px;overflow:auto;max-height:calc(100vh - 95px);';

        const info = document.createElement('div');
        info.textContent = mode === 'add'
            ? 'Hostnames are resolved directly against Entra devices through Microsoft Graph. No Add members blade is opened.'
            : 'Hostnames are resolved directly against the current group\'s direct device members through Microsoft Graph. The visible member list does not need to be scrolled.';
        info.style.cssText = 'margin-bottom:8px;';

        const context = document.createElement('div');
        context.style.cssText = 'margin-bottom:8px;font-weight:600;';
        context.textContent =
            `Microsoft Graph: ${graphAuthorization ? 'token detected' : 'waiting for token'}; ` +
            `Group: ${currentGroupId || 'waiting for group ID'}`;

        const textarea = document.createElement('textarea');
        textarea.placeholder = 'RQ010857\nRQ030261\nRQ103537';
        textarea.setAttribute('aria-label', 'Hostnames');
        textarea.style.cssText = [
            'width:100%',
            'height:170px',
            'box-sizing:border-box',
            'resize:vertical',
            'padding:8px',
            'border:1px solid var(--colorControlBorder, #8a8886)',
            'background:var(--colorControlBackground, #fff)',
            'color:var(--colorTextPrimary, #242424)',
            'font:12px Consolas,monospace'
        ].join(';');

        const controls = document.createElement('div');
        controls.style.cssText = 'display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;';

        const start = document.createElement('button');
        start.type = 'button';
        start.textContent = 'Resolve devices';
        start.style.cssText =
            'padding:6px 14px;border:1px solid #0078d4;background:#0078d4;' +
            'color:#fff;font-weight:600;cursor:pointer;';

        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.textContent = 'Cancel';
        cancel.disabled = true;
        cancel.style.cssText =
            'padding:6px 14px;border:1px solid var(--colorControlBorder, #8a8886);' +
            'background:var(--colorControlBackground, #fff);color:inherit;cursor:pointer;';

        const execute = document.createElement('button');
        execute.type = 'button';
        execute.disabled = true;
        execute.style.cssText = [
            'display:none',
            'padding:6px 14px',
            `border:1px solid ${mode === 'add' ? '#107c10' : '#a4262c'}`,
            `background:${mode === 'add' ? '#107c10' : '#a4262c'}`,
            'color:#fff',
            'font-weight:600',
            'cursor:pointer'
        ].join(';');

        const status = document.createElement('div');
        status.textContent = 'Ready';
        status.style.cssText = 'margin-top:10px;font-weight:600;';

        const preview = document.createElement('div');
        preview.style.cssText = [
            'display:none',
            'margin-top:8px',
            'max-height:220px',
            'overflow:auto',
            'border:1px solid var(--colorContainerBorderSecondary, #edebe9)',
            'background:var(--colorContainerBackgroundPrimary, #fff)',
            'font:11px Consolas,monospace'
        ].join(';');

        const logBox = document.createElement('div');
        logBox.style.cssText = [
            'margin-top:8px',
            'height:190px',
            'overflow:auto',
            'padding:8px',
            'background:var(--colorContainerBackgroundSecondary, #f3f2f1)',
            'border:1px solid var(--colorContainerBorderSecondary, #edebe9)',
            'font:11px Consolas,monospace',
            'white-space:pre-wrap'
        ].join(';');

        controls.append(start, cancel, execute);
        body.append(info, context, textarea, controls, status, preview, logBox);
        panel.append(header, body);
        document.body.appendChild(panel);

        ui = {
            mode,
            panel,
            context,
            textarea,
            start,
            cancel,
            execute,
            status,
            preview,
            log: logBox
        };

        const logObserver = new MutationObserver(scrollLogToBottom);
        logObserver.observe(logBox, { childList: true });

        const contextTimer = setInterval(() => {
            if (!panel.isConnected) {
                clearInterval(contextTimer);
                return;
            }

            context.textContent =
                `Microsoft Graph: ${graphAuthorization ? 'token detected' : 'waiting for token'}; ` +
                `Group: ${currentGroupId || 'waiting for group ID'}`;
        }, 500);

        cancel.onclick = () => {
            cancelRequested = true;
            cancel.disabled = true;
            log(
                'Cancellation requested. Microsoft Graph requests that already completed cannot be rolled back.'
            );
        };

        start.onclick = async () => {
            if (running) return;

            const hosts = parseHostnames(textarea.value);
            if (!hosts.length) {
                log('No hostnames were entered.');
                return;
            }

            running = true;
            cancelRequested = false;
            start.disabled = true;
            execute.disabled = true;
            execute.style.display = 'none';
            cancel.disabled = false;
            textarea.disabled = true;

            try {
                await prepareMode(hosts, mode);
            } catch (error) {
                if (cancelRequested) {
                    status.textContent = 'Cancelled';
                    log('Operation cancelled. No group membership change was applied.');
                } else {
                    status.textContent = 'Lookup failed';
                    log(`Lookup failed: ${String(error?.message || error)}`);
                }
            } finally {
                running = false;
                start.disabled = false;
                cancel.disabled = true;
                textarea.disabled = false;
            }
        };

        execute.onclick = async () => {
            if (running || !preparedAction?.items?.length) return;

            running = true;
            cancelRequested = false;
            start.disabled = true;
            execute.disabled = true;
            cancel.disabled = false;
            textarea.disabled = true;

            try {
                await executeMode();
            } catch (error) {
                if (cancelRequested) {
                    status.textContent = 'Cancelled';
                    log(
                        'Operation cancelled. Individual Microsoft Graph requests that already succeeded remain effective.'
                    );
                } else {
                    status.textContent =
                        mode === 'add' ? 'Add failed' : 'Remove failed';
                    log(
                        `${mode === 'add' ? 'Add' : 'Remove'} failed: ` +
                        `${String(error?.message || error)}`
                    );
                    execute.disabled = false;
                    execute.style.display = '';
                }
            } finally {
                running = false;
                start.disabled = false;
                cancel.disabled = true;
                textarea.disabled = false;
            }
        };

        centerPanel(panel);
        textarea.focus();
        scrollLogToBottom();
    }

    async function initialize() {
        console.info('[Entra Host List v18] Userscript injected into ReactBlade.', {
            version: VERSION,
            href: location.href,
            frameName: window.name || '(empty)'
        });

        const observer = new MutationObserver(() => {
            bindBulkOperationsButton();
            injectIntoNativeBulkMenu();
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });

        for (let i = 0; i < 160; i++) {
            if (bindBulkOperationsButton()) break;
            await sleep(250);
        }

        setInterval(() => {
            bindBulkOperationsButton();
            injectIntoNativeBulkMenu();
        }, 750);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, { once: true });
    } else {
        initialize();
    }
})();
