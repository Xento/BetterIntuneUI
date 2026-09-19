// ==UserScript==
// @name         Entra - Add Selected Members To Another Group
// @namespace    xento.betterintuneui
// @version      6.0.0
// @description  Add selected Entra group members (users/devices) to another group. Supports logical Select All via Graph.
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
    const VERSION = '6.0.0';
    const SCRIPT_ID = 'tm-entra-selected-members-to-group-v6';
    const PANEL_ID = SCRIPT_ID + '-panel';
    const MENU_ITEM_CLASS = SCRIPT_ID + '-menu-item';

    const CFG = {
        batchSize: 20,
        maxRetries: 3,
        retryMs: 1800,
        targetSearchLimit: 50,
        tokenWaitMs: 4000,

        // 'graph'    = Recommended. Select All + active search is remembered
        //              logically. The full matching member set is resolved through
        //              Graph only when the custom bulk action is executed.
        // 'native'   = Do not enhance Select All.
        selectAllMode: 'graph',

        preferCapturedPortalMemberQuery: true,
        maxGraphSelectAllMembers: 5000
    };

    let graphAuthorization = null;
    let sourceGroupId = null;
    let lastCapturedSourceMemberQuery = null;

    // Manual selections are cached by Entra Object ID.
    const selectionCache = new Map();

    // Logical "Select All for current filter".
    let logicalSelectAll = null;

    const boundBulkButtons = new WeakSet();

    let panel = null;
    let selectedTargetGroup = null;
    let currentSearchResults = [];
    let running = false;
    let statusToast = null;

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

    function isVisible(element) {
        if (!element) return false;
        const style = getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        return element.getClientRects().length > 0;
    }

    function chunk(items, size) {
        const result = [];
        for (let i = 0; i < items.length; i += size) {
            result.push(items.slice(i, i + size));
        }
        return result;
    }

    function isGraphUrl(url) {
        try {
            return new URL(String(url), location.href).hostname.toLowerCase() === 'graph.microsoft.com';
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
            for (const pair of headers) {
                if (Array.isArray(pair) && normalize(pair[0]) === wanted) {
                    return String(pair[1] || '');
                }
            }
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
        const match = text.match(
            new RegExp('groups/(' + guid + ')/(?:members|transitiveMembers)', 'i')
        );

        return match ? match[1].toLowerCase() : null;
    }

    function sourceMemberQueryInfo(value) {
        const text = String(value || '').trim();
        if (!text) return null;

        // Direct or relative Graph URL.
        try {
            const absolute = new URL(text, 'https://graph.microsoft.com/v1.0/');
            const match = absolute.pathname.match(
                /\/groups\/([0-9a-f-]{36})\/(members|transitiveMembers)$/i
            );

            if (
                match &&
                (
                    absolute.searchParams.has('$search') ||
                    absolute.searchParams.has('$filter')
                )
            ) {
                return {
                    groupId: match[1].toLowerCase(),
                    endpoint: normalize(match[2]) === 'transitivemembers'
                        ? 'transitiveMembers'
                        : 'members',
                    url: absolute.toString()
                };
            }
        } catch {}

        // Graph batch body.
        try {
            const parsed = JSON.parse(text);
            const requests = Array.isArray(parsed?.requests) ? parsed.requests : [];

            for (const request of requests) {
                const info = sourceMemberQueryInfo(request?.url || '');
                if (info) return info;
            }
        } catch {}

        return null;
    }

    function captureGraphContext(url, body, headers) {
        if (!isGraphUrl(url)) return;

        const auth = getHeaderValue(headers, 'Authorization');
        if (/^Bearer\s+\S+/i.test(auth)) {
            graphAuthorization = auth;
        }

        const groupId =
            extractGroupIdFromText(url) ||
            extractGroupIdFromText(body);

        if (groupId) sourceGroupId = groupId;

        const queryInfo =
            sourceMemberQueryInfo(url) ||
            sourceMemberQueryInfo(body);

        if (queryInfo) {
            lastCapturedSourceMemberQuery = {
                ...queryInfo,
                capturedAt: now()
            };
        }
    }

    function installNetworkHooks() {
        try {
            const originalFetch = PAGE.fetch;

            if (typeof originalFetch === 'function' && !originalFetch.__tmSelectedToGroupV6) {
                const wrapped = async function (...args) {
                    const request = args[0];
                    const init = args[1] || {};

                    const url =
                        typeof request === 'string' || request instanceof URL
                            ? String(request)
                            : request?.url || '';

                    if (isGraphUrl(url)) {
                        captureGraphContext(
                            url,
                            init.body !== undefined ? init.body : '',
                            init.headers || request?.headers || null
                        );
                    }

                    return originalFetch.apply(this, args);
                };

                Object.defineProperty(wrapped, '__tmSelectedToGroupV6', {
                    value: true
                });

                PAGE.fetch = wrapped;
            }
        } catch (error) {
            console.warn('[Selected -> Group] fetch hook failed:', error);
        }

        try {
            const XHR = PAGE.XMLHttpRequest;
            if (!XHR || XHR.prototype.__tmSelectedToGroupV6) return;

            const originalOpen = XHR.prototype.open;
            const originalSend = XHR.prototype.send;
            const originalSetHeader = XHR.prototype.setRequestHeader;

            XHR.prototype.open = function (method, url, ...rest) {
                this.__tmSelectedToGroupUrl = String(url || '');
                this.__tmSelectedToGroupHeaders = {};
                return originalOpen.call(this, method, url, ...rest);
            };

            XHR.prototype.setRequestHeader = function (name, value) {
                this.__tmSelectedToGroupHeaders ||= {};
                this.__tmSelectedToGroupHeaders[name] = value;
                return originalSetHeader.call(this, name, value);
            };

            XHR.prototype.send = function (body) {
                const url = this.__tmSelectedToGroupUrl || '';

                if (isGraphUrl(url)) {
                    captureGraphContext(
                        url,
                        body,
                        this.__tmSelectedToGroupHeaders || {}
                    );
                }

                return originalSend.call(this, body);
            };

            Object.defineProperty(XHR.prototype, '__tmSelectedToGroupV6', {
                value: true
            });
        } catch (error) {
            console.warn('[Selected -> Group] XHR hook failed:', error);
        }
    }

    installNetworkHooks();

    function graphHeaders(extra = {}) {
        if (!graphAuthorization) {
            throw new Error(
                'Graph token has not yet been captured from the current portal session.'
            );
        }

        return {
            Accept: 'application/json',
            Authorization: graphAuthorization,
            ...extra
        };
    }

    async function graphFetch(url, options = {}) {
        return PAGE.fetch(url, {
            ...options,
            headers: {
                ...graphHeaders(),
                ...(options.headers || {})
            }
        });
    }

    async function waitForToken() {
        const started = now();

        while (!graphAuthorization && now() - started < CFG.tokenWaitMs) {
            await sleep(100);
        }

        return !!graphAuthorization;
    }

    function cellText(row, key) {
        return String(
            row.querySelector(
                `[data-automationid="DetailsRowCell"][data-automation-key="${key}"]`
            )?.textContent || ''
        ).trim();
    }

    function parseMemberRow(row) {
        if (!row) return null;

        const id = cellText(row, 'id');
        const objectType = cellText(row, 'objectType');
        const displayName = cellText(row, 'displayName');

        if (!looksLikeGuid(id)) return null;
        if (!['device', 'user'].includes(normalize(objectType))) return null;

        return {
            id,
            objectType: normalize(objectType) === 'device' ? 'Device' : 'User',
            displayName: displayName || id,
            mail: cellText(row, 'mail'),
            deviceId: cellText(row, 'deviceId')
        };
    }

    function getRowCheckbox(row) {
        return row?.querySelector(
            '[data-automationid="DetailsRowCheck"][role="checkbox"]'
        ) || null;
    }

    function rowIsSelected(row) {
        if (!row) return false;

        // Primary signal for an individually selected Fluent DetailsRow.
        const checkbox = getRowCheckbox(row);
        const checked = normalize(checkbox?.getAttribute('aria-checked'));

        if (checked === 'true') return true;
        if (checked === 'false') return false;

        // Fallback signals used by different Fluent UI builds.
        if (normalize(row.getAttribute('aria-selected')) === 'true') return true;
        if (row.classList.contains('is-selected')) return true;
        if (checkbox?.classList.contains('is-checked')) return true;
        if (checkbox?.querySelector('.is-checked')) return true;

        return false;
    }

    function getActiveMemberTabPanel() {
        const panels = [
            ...document.querySelectorAll('[role="tabpanel"]')
        ];

        return panels.find(panel => {
            if (panel.getAttribute('aria-hidden') === 'true') return false;
            if (!isVisible(panel)) return false;

            return !!panel.querySelector(
                '[role="grid"] [role="row"][data-automationid="DetailsRow"]'
            );
        }) || null;
    }

    function getActiveMemberGrid() {
        const panel = getActiveMemberTabPanel();
        if (!panel) return null;

        // There should normally be one DetailsList grid in the active member tab.
        // Prefer a grid which actually contains member rows.
        return [
            ...panel.querySelectorAll('[role="grid"]')
        ].find(grid =>
            grid.querySelector(
                '[role="row"][data-automationid="DetailsRow"]'
            )
        ) || null;
    }

    function getActiveMemberRows() {
        const grid = getActiveMemberGrid();
        if (!grid) return [];

        return [
            ...grid.querySelectorAll(
                '[role="row"][data-automationid="DetailsRow"]'
            )
        ];
    }

    function selectedMembersFromActiveDom() {
        const result = new Map();

        for (const row of getActiveMemberRows()) {
            if (!rowIsSelected(row)) continue;

            const member = parseMemberRow(row);
            if (!member) continue;

            result.set(normalize(member.id), member);
        }

        return [...result.values()];
    }

    function syncVisibleSelection() {
        // IMPORTANT:
        // Never scan every DetailsRow in the complete ReactBlade. Fluent/React may
        // keep another tab/list instance mounted. An unselected duplicate row from
        // such an inactive list could otherwise delete a valid selected member.
        const rows = getActiveMemberRows();

        for (const row of rows) {
            const member = parseMemberRow(row);
            if (!member) continue;

            const key = normalize(member.id);

            if (rowIsSelected(row)) {
                selectionCache.set(key, member);
            } else {
                // Only remove the explicitly unselected instance from the ACTIVE
                // member list. Cached selections that scrolled out of the DOM stay
                // available for the custom bulk action.
                selectionCache.delete(key);
            }
        }

        updateSelectionBadge();
    }

    function selectedMembers() {
        // Read the current marked rows directly at action time first. This is the
        // authoritative source for ordinary manual selection.
        const direct = selectedMembersFromActiveDom();

        for (const member of direct) {
            selectionCache.set(normalize(member.id), member);
        }

        // Then reconcile all currently rendered rows in the active grid.
        syncVisibleSelection();

        // Re-add the direct snapshot in case Fluent changed a row while opening
        // the contextual menu. A row that was selected when the action started
        // must not be lost because of a transient menu/render update.
        for (const member of direct) {
            selectionCache.set(normalize(member.id), member);
        }

        return [...selectionCache.values()];
    }

    function updateSelectionBadge() {
        const countNode = panel?.querySelector('[data-role="selection-count"]');
        if (!countNode) return;

        const values = [...selectionCache.values()];
        const devices = values.filter(x => x.objectType === 'Device').length;
        const users = values.filter(x => x.objectType === 'User').length;

        const text =
            `${values.length} selected (${devices} device${devices === 1 ? '' : 's'}, ` +
            `${users} user${users === 1 ? '' : 's'})`;

        if (countNode.textContent !== text) {
            countNode.textContent = text;
        }
    }

    function clearSelectionState(reason = '') {
        selectionCache.clear();
        logicalSelectAll = null;
        updateSelectionBadge();

        if (reason) {
            console.info('[Selected -> Group] Selection cache cleared:', reason);
        }
    }

    function getHeaderSelectAllFromTarget(target) {
        if (!(target instanceof Element)) return null;

        return target.closest(
            '[role="checkbox"][data-selection-toggle="true"].ms-DetailsHeader-check'
        );
    }

    function getActiveSearchContext() {
        const selectedTab = getActiveMemberTabPanel();

        const input = selectedTab?.querySelector(
            'input[role="searchbox"], input.ms-SearchBox-field'
        );

        if (!input || !isVisible(input)) return null;

        const labelledBy = selectedTab.getAttribute('aria-labelledby');
        const tab =
            (labelledBy && document.getElementById(labelledBy)) ||
            document.querySelector('button[role="tab"][aria-selected="true"]');

        const tabText = normalize(
            tab?.getAttribute('name') ||
            tab?.getAttribute('data-content') ||
            tab?.textContent ||
            ''
        );

        return {
            input,
            query: String(input.value || '').trim(),
            endpoint: tabText.includes('all members')
                ? 'transitiveMembers'
                : 'members'
        };
    }

    function logicalSelectAllStillValid() {
        if (!logicalSelectAll) return false;

        const current = getActiveSearchContext();
        if (!current) return false;

        return (
            normalize(current.query) === normalize(logicalSelectAll.query) &&
            current.endpoint === logicalSelectAll.endpoint
        );
    }

    function showToast(message, kind = 'normal', hideAfter = 0) {
        if (!statusToast || !document.contains(statusToast)) {
            statusToast = document.createElement('div');
            statusToast.style.cssText = [
                'position:fixed',
                'top:18px',
                'left:50%',
                'transform:translateX(-50%)',
                'z-index:2147483647',
                'max-width:min(760px,calc(100vw - 40px))',
                'padding:9px 14px',
                'border:1px solid var(--colorContainerBorderPrimary,#8a8886)',
                'background:var(--colorContainerBackgroundPrimary,#fff)',
                'color:var(--colorTextPrimary,#242424)',
                'box-shadow:0 4px 18px rgba(0,0,0,.28)',
                'font:13px "Segoe UI",Arial,sans-serif',
                'pointer-events:none'
            ].join(';');
            document.body.appendChild(statusToast);
        }

        statusToast.textContent = message;
        statusToast.style.color =
            kind === 'error'
                ? 'var(--colorTextError,#f1707b)'
                : 'var(--colorTextPrimary,#242424)';

        if (hideAfter > 0) {
            const current = statusToast;
            setTimeout(() => {
                if (statusToast === current) {
                    current.remove();
                    statusToast = null;
                }
            }, hideAfter);
        }
    }

    function installSelectionTracking() {
        // Row checkbox click: wait until Fluent has updated aria-checked.
        document.addEventListener('click', event => {
            if (!(event.target instanceof Element)) return;

            const rowCheckbox = event.target.closest(
                '[data-automationid="DetailsRowCheck"][role="checkbox"]'
            );

            const headerCheckbox = getHeaderSelectAllFromTarget(event.target);

            if (rowCheckbox && !headerCheckbox) {
                logicalSelectAll = null;

                for (const delay of [0, 30, 90, 180]) {
                    setTimeout(syncVisibleSelection, delay);
                }
            }

            // Refresh resets the portal list/selection.
            if (event.target.closest('button[data-testid="RefreshCmdBtn"]')) {
                clearSelectionState('Refresh');
            }

            // Switching Direct/All members invalidates the previous selection snapshot.
            if (event.target.closest('button[role="tab"]')) {
                setTimeout(() => clearSelectionState('Member tab changed'), 0);
            }
        }, true);

        // Search changes invalidate manual and logical selection.
        document.addEventListener('input', event => {
            const target = event.target;

            if (
                target instanceof HTMLInputElement &&
                target.matches('input[role="searchbox"], input.ms-SearchBox-field')
            ) {
                clearSelectionState('Search changed');
            }
        }, true);

        // Observe both row aria-selected and checkbox aria-checked.
        let queued = false;

        const queueSync = () => {
            if (queued) return;
            queued = true;

            requestAnimationFrame(() => {
                queued = false;
                syncVisibleSelection();
            });
        };

        const observer = new MutationObserver(mutations => {
            for (const mutation of mutations) {
                const target =
                    mutation.target instanceof Element
                        ? mutation.target
                        : mutation.target?.parentElement;

                if (target?.closest?.(`#${PANEL_ID}`)) continue;

                if (
                    mutation.type === 'attributes' &&
                    (
                        mutation.attributeName === 'aria-selected' ||
                        mutation.attributeName === 'aria-checked' ||
                        mutation.attributeName === 'class'
                    )
                ) {
                    if (
                        target?.matches?.(
                            '[role="row"][data-automationid="DetailsRow"], ' +
                            '[data-automationid="DetailsRowCheck"][role="checkbox"]'
                        ) ||
                        target?.closest?.(
                            '[role="row"][data-automationid="DetailsRow"]'
                        )
                    ) {
                        queueSync();
                    }
                }

                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (!(node instanceof Element)) continue;

                        if (
                            node.matches?.(
                                '[role="row"][data-automationid="DetailsRow"]'
                            ) ||
                            node.querySelector?.(
                                '[role="row"][data-automationid="DetailsRow"]'
                            )
                        ) {
                            queueSync();
                            break;
                        }
                    }
                }
            }
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['aria-selected', 'aria-checked', 'class']
        });
    }

    function installSelectAllTracking() {
        document.addEventListener('click', event => {
            const header = getHeaderSelectAllFromTarget(event.target);
            if (!header) return;

            const before = normalize(header.getAttribute('aria-checked'));
            const context = getActiveSearchContext();

            // If it was fully checked, the native click means "clear all".
            if (before === 'true') {
                setTimeout(() => clearSelectionState('Select All cleared'), 0);
                return;
            }

            if (
                normalize(CFG.selectAllMode) === 'graph' &&
                context?.query
            ) {
                const pending = {
                    query: context.query,
                    endpoint: context.endpoint,
                    activatedAt: now()
                };

                // Do not block Microsoft's native visual selection.
                setTimeout(() => {
                    const after = normalize(header.getAttribute('aria-checked'));

                    if (after === 'true' || after === 'mixed') {
                        logicalSelectAll = pending;

                        console.info(
                            '[Selected -> Group] Logical Select All enabled.',
                            pending
                        );

                        showToast(
                            `Select all remembered for "${pending.query}". ` +
                            'All matching User/Device members will be resolved through Graph when the custom bulk action is used.',
                            'normal',
                            2500
                        );
                    }
                }, 0);
            }
        }, true);
    }

    function getBulkOperationsButton() {
        return document.querySelector('button[data-testid="bulkOperations"]');
    }

    function getBulkMenu(button = getBulkOperationsButton()) {
        if (!button) return null;

        const id = button.getAttribute('aria-controls');
        if (id) {
            const controlled = document.getElementById(id);
            if (controlled) return controlled;
        }

        return document
            .querySelector('button[data-testid="bulkGroupImportMember"]')
            ?.closest('[role="menu"]') || null;
    }

    function cleanClone(root) {
        for (const element of [root, ...root.querySelectorAll('*')]) {
            element.removeAttribute('id');
            element.removeAttribute('elementtiming');
            element.removeAttribute('aria-controls');
            element.removeAttribute('aria-labelledby');
            element.removeAttribute('aria-describedby');
            element.removeAttribute('data-focuszone-id');
        }
    }

    function closeNativeBulkMenu() {
        try {
            document.activeElement?.dispatchEvent(
                new KeyboardEvent('keydown', {
                    key: 'Escape',
                    code: 'Escape',
                    keyCode: 27,
                    which: 27,
                    bubbles: true
                })
            );
        } catch {}
    }

    function graphSearchEscape(value) {
        return String(value || '')
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"');
    }

    function capturedPortalQueryForLogicalSelection(state) {
        if (!CFG.preferCapturedPortalMemberQuery) return null;
        if (!lastCapturedSourceMemberQuery || !sourceGroupId) return null;

        if (
            normalize(lastCapturedSourceMemberQuery.groupId) !== normalize(sourceGroupId) ||
            lastCapturedSourceMemberQuery.endpoint !== state.endpoint
        ) {
            return null;
        }

        let decoded = lastCapturedSourceMemberQuery.url;
        try {
            decoded = decodeURIComponent(decoded);
        } catch {}

        if (!normalize(decoded).includes(normalize(state.query))) {
            return null;
        }

        try {
            const url = new URL(lastCapturedSourceMemberQuery.url);
            url.searchParams.delete('$skiptoken');
            url.searchParams.set('$top', '999');
            return url.toString();
        } catch {
            return null;
        }
    }

    function fallbackLogicalSelectAllUrl(state) {
        const url = new URL(
            `https://graph.microsoft.com/v1.0/groups/${sourceGroupId}/${state.endpoint}`
        );

        url.searchParams.set(
            '$search',
            `"displayName:${graphSearchEscape(state.query)}"`
        );
        url.searchParams.set(
            '$select',
            'id,displayName,mail,deviceId'
        );
        url.searchParams.set('$count', 'true');
        url.searchParams.set('$top', '999');

        return url.toString();
    }

    function graphMemberToLocalMember(item) {
        const type = normalize(item?.['@odata.type']);

        if (type.endsWith('.device')) {
            return {
                id: item.id,
                objectType: 'Device',
                displayName: item.displayName || item.id,
                mail: '',
                deviceId: item.deviceId || ''
            };
        }

        if (type.endsWith('.user')) {
            return {
                id: item.id,
                objectType: 'User',
                displayName: item.displayName || item.id,
                mail: item.mail || '',
                deviceId: ''
            };
        }

        return null;
    }

    async function resolveLogicalSelectAllMembers(state) {
        if (!state) return [];

        if (!logicalSelectAllStillValid()) {
            logicalSelectAll = null;
            throw new Error(
                'The search or member tab changed after Select All. Click Select All again.'
            );
        }

        if (!await waitForToken()) {
            throw new Error(
                'No Graph token was captured yet. Let the member list finish loading or click Refresh once.'
            );
        }

        if (!sourceGroupId) {
            throw new Error(
                'The source group ID has not yet been captured from the current member list.'
            );
        }

        const captured = capturedPortalQueryForLogicalSelection(state);
        let nextUrl = captured || fallbackLogicalSelectAllUrl(state);

        const resolved = new Map();

        console.info(
            '[Selected -> Group] Resolving logical Select All through Graph.',
            {
                query: state.query,
                endpoint: state.endpoint,
                queryMode: captured ? 'captured-portal-query' : 'fallback-displayName-search'
            }
        );

        while (nextUrl) {
            showToast(
                `Resolving all matches for "${state.query}" through Graph … ` +
                `${resolved.size} User/Device item(s)`
            );

            const response = await graphFetch(nextUrl, {
                method: 'GET',
                headers: {
                    ConsistencyLevel: 'eventual'
                }
            });

            if (!response.ok) {
                const text = await response.text().catch(() => '');

                throw new Error(
                    `Source member search failed: HTTP ${response.status}` +
                    (text ? ` - ${text.slice(0, 300)}` : '')
                );
            }

            const body = await response.json();

            for (const item of body.value || []) {
                const member = graphMemberToLocalMember(item);
                if (!member || !looksLikeGuid(member.id)) continue;

                resolved.set(normalize(member.id), member);

                if (resolved.size > CFG.maxGraphSelectAllMembers) {
                    throw new Error(
                        `Safety limit reached (${CFG.maxGraphSelectAllMembers} User/Device items). Narrow the search.`
                    );
                }
            }

            nextUrl = body['@odata.nextLink'] || null;
        }

        if (!resolved.size) {
            throw new Error(
                `Graph returned no User/Device members for "${state.query}".`
            );
        }

        selectionCache.clear();

        for (const [id, member] of resolved) {
            selectionCache.set(id, member);
        }

        showToast(
            `Resolved ${resolved.size} matching User/Device member(s) for "${state.query}".`,
            'normal',
            1800
        );

        return [...resolved.values()];
    }

    async function membersForBulkAction() {
        if (
            normalize(CFG.selectAllMode) === 'graph' &&
            logicalSelectAll
        ) {
            return resolveLogicalSelectAllMembers(logicalSelectAll);
        }

        const members = selectedMembers();

        console.info(
            '[Selected -> Group] Manual selection snapshot.',
            {
                activeDomSelected: selectedMembersFromActiveDom().map(m => ({
                    id: m.id,
                    type: m.objectType,
                    name: m.displayName
                })),
                cachedCount: members.length
            }
        );

        return members;
    }

    function createMenuItem(referenceButton) {
        const sourceLi = referenceButton?.closest('li[role="presentation"]');
        if (!sourceLi) return null;

        const li = sourceLi.cloneNode(true);
        cleanClone(li);
        li.classList.add(MENU_ITEM_CLASS);

        const button = li.querySelector('button[role="menuitem"]');
        if (!button) return null;

        button.classList.add(MENU_ITEM_CLASS);
        button.dataset.testid = 'tmAddSelectedToAnotherGroup';
        button.setAttribute('name', 'Add selected to another group');
        button.setAttribute(
            'data-telemetryname',
            'Tampermonkey - Add selected members to another group'
        );
        button.setAttribute('aria-disabled', 'false');
        button.removeAttribute('disabled');
        button.setAttribute('tabindex', '-1');

        const label =
            button.querySelector('.ms-ContextualMenu-itemText') ||
            button.querySelector('span');

        if (label) {
            label.textContent = 'Add selected to another group';
        }

        button.addEventListener('click', async event => {
            event.preventDefault();
            event.stopPropagation();

            closeNativeBulkMenu();

            try {
                const members = await membersForBulkAction();

                if (!members.length) {
                    alert('No User or Device is currently selected.');
                    return;
                }

                console.info(
                    '[Selected -> Group] Opening target group search.',
                    {
                        selectedMembers: members.length,
                        logicalSelectAll: !!logicalSelectAll
                    }
                );

                setTimeout(() => openPanel(members), 0);
            } catch (error) {
                console.error(
                    '[Selected -> Group] Could not prepare selected members:',
                    error
                );

                showToast(
                    `Could not prepare selected members: ${String(error?.message || error)}`,
                    'error',
                    5000
                );
            }
        });

        return li;
    }

    function updateMenuAria(list) {
        const buttons = [
            ...list.querySelectorAll(
                ':scope > li[role="presentation"] > button[role="menuitem"]'
            )
        ];

        buttons.forEach((button, index) => {
            button.setAttribute('aria-posinset', String(index + 1));
            button.setAttribute('aria-setsize', String(buttons.length));
        });
    }

    function injectMenuItem(menu = getBulkMenu()) {
        if (!menu) return false;

        const list =
            menu.querySelector('ul.ms-ContextualMenu-list') ||
            menu.querySelector('ul[role="presentation"]');

        if (!list) return false;
        if (list.querySelector(`.${MENU_ITEM_CLASS}`)) return true;

        const importButton =
            list.querySelector('button[data-testid="bulkGroupImportMember"]') ||
            list.querySelector('button[role="menuitem"]');

        if (!importButton) return false;

        const li = createMenuItem(importButton);
        if (!li) return false;

        const importLi = importButton.closest('li[role="presentation"]');

        if (importLi?.parentElement === list) {
            importLi.insertAdjacentElement('afterend', li);
        } else {
            list.prepend(li);
        }

        updateMenuAria(list);

        console.info('[Selected -> Group] Bulk menu item injected.');
        return true;
    }

    function scheduleInjection(button) {
        for (const delay of [0, 20, 60, 120, 250, 500, 900]) {
            setTimeout(() => injectMenuItem(getBulkMenu(button)), delay);
        }
    }

    function bindBulkOperations() {
        const button = getBulkOperationsButton();
        if (!button) return false;

        if (!boundBulkButtons.has(button)) {
            boundBulkButtons.add(button);

            console.info('[Selected -> Group] bulkOperations button detected.');

            button.addEventListener('click', () => {
                syncVisibleSelection();
                scheduleInjection(button);
            }, true);

            button.addEventListener('keydown', event => {
                if (['Enter', ' ', 'ArrowDown'].includes(event.key)) {
                    syncVisibleSelection();
                    scheduleInjection(button);
                }
            }, true);
        }

        if (button.getAttribute('aria-expanded') === 'true') {
            scheduleInjection(button);
        }

        return true;
    }

    function selectedHasDevices(members) {
        return members.some(member => member.objectType === 'Device');
    }

    function groupCompatibility(group, members) {
        const groupTypes = (group.groupTypes || []).map(normalize);
        const dynamic = groupTypes.includes('dynamicmembership');
        const unified = groupTypes.includes('unified');

        if (dynamic) {
            return { allowed: false, reason: 'Dynamic membership' };
        }

        if (sourceGroupId && normalize(group.id) === normalize(sourceGroupId)) {
            return { allowed: false, reason: 'Current source group' };
        }

        if (unified && selectedHasDevices(members)) {
            return {
                allowed: false,
                reason: 'Microsoft 365 groups cannot contain devices'
            };
        }

        if (!unified && group.securityEnabled !== true) {
            return {
                allowed: false,
                reason: 'Not a supported security group'
            };
        }

        return {
            allowed: true,
            reason: group.isAssignableToRole
                ? 'Role-assignable group: additional permissions may be required'
                : ''
        };
    }

    function encodeSearchTerm(value) {
        return String(value || '')
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"');
    }

    async function searchGroups(query, members) {
        if (!await waitForToken()) {
            throw new Error(
                'No Graph token was captured yet. Let the member list finish loading or click Refresh once.'
            );
        }

        const q = String(query || '').trim();
        if (q.length < 2) {
            throw new Error('Enter at least 2 characters.');
        }

        const search = encodeURIComponent(
            `"displayName:${encodeSearchTerm(q)}"`
        );

        const select = [
            'id',
            'displayName',
            'description',
            'groupTypes',
            'securityEnabled',
            'mailEnabled',
            'isAssignableToRole'
        ].join(',');

        const response = await graphFetch(
            'https://graph.microsoft.com/v1.0/groups' +
            `?$search=${search}` +
            `&$select=${select}` +
            `&$top=${CFG.targetSearchLimit}` +
            '&$count=true',
            {
                method: 'GET',
                headers: {
                    ConsistencyLevel: 'eventual'
                }
            }
        );

        if (!response.ok) {
            const body = await response.text().catch(() => '');

            throw new Error(
                `Group search failed: HTTP ${response.status}` +
                (body ? ` - ${body.slice(0, 250)}` : '')
            );
        }

        const body = await response.json();
        const wanted = normalize(q);

        return (body.value || [])
            .map(group => ({
                ...group,
                compatibility: groupCompatibility(group, members)
            }))
            .sort((a, b) => {
                const an = normalize(a.displayName);
                const bn = normalize(b.displayName);

                const rank = value => {
                    if (value === wanted) return 0;
                    if (value.startsWith(wanted)) return 1;
                    if (value.includes(wanted)) return 2;
                    return 3;
                };

                const diff = rank(an) - rank(bn);
                return diff || an.localeCompare(bn);
            });
    }

    function groupTypeText(group) {
        const types = (group.groupTypes || []).map(normalize);

        if (types.includes('dynamicmembership')) {
            return types.includes('unified')
                ? 'Dynamic Microsoft 365'
                : 'Dynamic Security';
        }

        if (types.includes('unified')) return 'Microsoft 365';
        if (group.securityEnabled) return 'Security';
        return 'Group';
    }

    function ensureStyle() {
        if (document.getElementById(SCRIPT_ID + '-style')) return;

        const style = document.createElement('style');
        style.id = SCRIPT_ID + '-style';
        style.textContent = `
#${PANEL_ID} {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: min(760px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    z-index: 2147483646;
    background: var(--colorContainerBackgroundPrimary, #fff);
    color: var(--colorTextPrimary, #242424);
    border: 1px solid var(--colorContainerBorderPrimary, #d1d1d1);
    box-shadow: 0 12px 40px rgba(0,0,0,.38);
    font-family: "Segoe UI", Arial, sans-serif;
    display: flex;
    flex-direction: column;
}
#${PANEL_ID} * { box-sizing: border-box; }
#${PANEL_ID} .tm-head {
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:12px 14px;
    border-bottom:1px solid var(--colorContainerBorderPrimary,#ddd);
    font-weight:600;
    font-size:16px;
}
#${PANEL_ID} .tm-body {
    padding:14px;
    overflow:auto;
}
#${PANEL_ID} .tm-row {
    display:flex;
    gap:8px;
    align-items:center;
}
#${PANEL_ID} input {
    flex:1;
    min-height:34px;
    border:1px solid var(--colorControlBorder,#8a8886);
    background:var(--colorControlBackground,#fff);
    color:var(--colorTextPrimary,#242424);
    padding:6px 8px;
    font:inherit;
}
#${PANEL_ID} button {
    min-height:34px;
    padding:5px 12px;
    border:1px solid var(--colorControlBorder,#8a8886);
    background:var(--colorButtonBackgroundSecondary,#fff);
    color:var(--colorTextPrimary,#242424);
    cursor:pointer;
    font:inherit;
}
#${PANEL_ID} button.primary {
    background:var(--colorButtonBackgroundPrimary,#0078d4);
    color:var(--colorButtonForegroundPrimary,#fff);
    border-color:var(--colorButtonBackgroundPrimary,#0078d4);
}
#${PANEL_ID} button:disabled { opacity:.5; cursor:default; }
#${PANEL_ID} .tm-muted {
    color:var(--colorTextSecondary,#666);
    font-size:12px;
}
#${PANEL_ID} .tm-selected {
    margin:0 0 12px;
    padding:9px;
    border:1px solid var(--colorContainerBorderPrimary,#ddd);
}
#${PANEL_ID} .tm-results {
    margin-top:10px;
    border:1px solid var(--colorContainerBorderPrimary,#ddd);
    max-height:280px;
    overflow:auto;
}
#${PANEL_ID} .tm-group {
    padding:9px 10px;
    border-bottom:1px solid var(--colorContainerBorderPrimary,#ddd);
    cursor:pointer;
}
#${PANEL_ID} .tm-group:last-child { border-bottom:0; }
#${PANEL_ID} .tm-group:hover {
    background:var(--colorControlBackgroundHover,rgba(0,0,0,.06));
}
#${PANEL_ID} .tm-group.chosen {
    outline:2px solid var(--colorControlBorderFocus,#0078d4);
    outline-offset:-2px;
}
#${PANEL_ID} .tm-group.disabled {
    opacity:.55;
    cursor:not-allowed;
}
#${PANEL_ID} .tm-group-name { font-weight:600; }
#${PANEL_ID} .tm-error { color:var(--colorTextError,#a4262c); font-size:12px; }
#${PANEL_ID} .tm-ok { color:var(--colorTextSuccess,#107c10); font-size:12px; }
#${PANEL_ID} .tm-log {
    margin-top:12px;
    padding:8px;
    height:120px;
    overflow:auto;
    white-space:pre-wrap;
    font-family:Consolas,monospace;
    font-size:11px;
    border:1px solid var(--colorContainerBorderPrimary,#ddd);
    background:var(--colorContainerBackgroundSecondary,rgba(0,0,0,.03));
}
#${PANEL_ID} .tm-footer {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:8px;
    padding:10px 14px;
    border-top:1px solid var(--colorContainerBorderPrimary,#ddd);
}
`;
        document.head.appendChild(style);
    }

    function panelLog(message) {
        const log = panel?.querySelector('[data-role="log"]');
        if (!log) return;

        const stamp = new Date().toLocaleTimeString();
        log.textContent += `${stamp}  ${message}\n`;
        log.scrollTop = log.scrollHeight;
    }

    function renderTargetResults(members) {
        const container = panel?.querySelector('[data-role="results"]');
        if (!container) return;

        container.replaceChildren();

        if (!currentSearchResults.length) {
            const empty = document.createElement('div');
            empty.className = 'tm-group tm-muted';
            empty.textContent = 'No groups found.';
            container.appendChild(empty);
            return;
        }

        for (const group of currentSearchResults) {
            const item = document.createElement('div');
            item.className = 'tm-group';

            if (!group.compatibility.allowed) item.classList.add('disabled');
            if (selectedTargetGroup?.id === group.id) item.classList.add('chosen');

            const name = document.createElement('div');
            name.className = 'tm-group-name';
            name.textContent = group.displayName || group.id;

            const meta = document.createElement('div');
            meta.className = 'tm-muted';
            meta.textContent = `${groupTypeText(group)} · ${group.id}`;

            item.append(name, meta);

            if (group.compatibility.reason) {
                const reason = document.createElement('div');
                reason.className =
                    group.compatibility.allowed ? 'tm-muted' : 'tm-error';
                reason.textContent = group.compatibility.reason;
                item.append(reason);
            }

            if (group.description) {
                const description = document.createElement('div');
                description.className = 'tm-muted';
                description.textContent = group.description;
                item.append(description);
            }

            if (group.compatibility.allowed) {
                item.addEventListener('click', () => {
                    selectedTargetGroup = group;
                    renderTargetResults(members);
                    updateExecuteButton(members);
                });
            }

            container.appendChild(item);
        }
    }

    function updateExecuteButton(members) {
        const execute = panel?.querySelector('[data-role="execute"]');
        const target = panel?.querySelector('[data-role="target"]');

        if (!execute || !target) return;

        target.textContent = selectedTargetGroup
            ? `Target: ${selectedTargetGroup.displayName} (${selectedTargetGroup.id})`
            : 'Target: not selected';

        execute.disabled = !selectedTargetGroup || !members.length || running;
        execute.textContent = selectedTargetGroup
            ? `Add ${members.length} selected member${members.length === 1 ? '' : 's'}`
            : 'Select a target group';
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
                `Graph batch failed: HTTP ${response.status}` +
                (text ? ` - ${text.slice(0, 250)}` : '')
            );
        }

        return response.json();
    }

    function alreadyMemberMessage(message) {
        const text = normalize(message);

        return text.includes('already exist') ||
               text.includes('already a member') ||
               text.includes('object references already exist');
    }

    async function addChunk(targetGroupId, items) {
        let pending = [...items];
        const results = [];

        for (let attempt = 1; attempt <= CFG.maxRetries && pending.length; attempt++) {
            const idMap = new Map();

            const requests = pending.map((member, index) => {
                const requestId = String(index + 1);
                idMap.set(requestId, member);

                return {
                    id: requestId,
                    method: 'POST',
                    url: `/groups/${targetGroupId}/members/$ref`,
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: {
                        '@odata.id':
                            `https://graph.microsoft.com/v1.0/directoryObjects/${member.id}`
                    }
                };
            });

            const response = await sendGraphBatch(requests);
            const retry = [];

            for (const sub of response.responses || []) {
                const member = idMap.get(String(sub.id));
                if (!member) continue;

                const status = Number(sub.status || 0);
                const message =
                    sub.body?.error?.message ||
                    sub.body?.message ||
                    '';

                if (status === 204) {
                    results.push({ member, result: 'added', status });
                    continue;
                }

                if (status === 400 && alreadyMemberMessage(message)) {
                    results.push({
                        member,
                        result: 'already-member',
                        status,
                        message
                    });
                    continue;
                }

                if (
                    [429, 503, 504].includes(status) &&
                    attempt < CFG.maxRetries
                ) {
                    retry.push(member);
                    continue;
                }

                results.push({
                    member,
                    result: 'failed',
                    status,
                    message: message || `HTTP ${status}`
                });
            }

            pending = retry;

            if (pending.length) {
                panelLog(
                    `${pending.length} transient request(s); retrying in ${CFG.retryMs} ms.`
                );
                await sleep(CFG.retryMs);
            }
        }

        for (const member of pending) {
            results.push({
                member,
                result: 'failed',
                status: 0,
                message: 'Retry limit reached.'
            });
        }

        return results;
    }

    async function executeAdd(members) {
        if (!selectedTargetGroup || running) return;

        running = true;
        updateExecuteButton(members);

        try {
            panelLog(
                `Adding ${members.length} selected member(s) to "${selectedTargetGroup.displayName}".`
            );

            const allResults = [];

            for (const [index, part] of chunk(members, CFG.batchSize).entries()) {
                panelLog(`Batch ${index + 1}: ${part.length} member(s).`);
                allResults.push(...await addChunk(selectedTargetGroup.id, part));
            }

            const added = allResults.filter(r => r.result === 'added');
            const existing = allResults.filter(r => r.result === 'already-member');
            const failed = allResults.filter(r => r.result === 'failed');

            panelLog(
                `Completed: ${added.length} added, ${existing.length} already member, ${failed.length} failed.`
            );

            for (const item of failed) {
                panelLog(
                    `FAILED ${item.member.objectType} ${item.member.displayName}: ${item.message}`
                );
            }

            const resultNode = panel.querySelector('[data-role="result"]');
            resultNode.className = failed.length ? 'tm-error' : 'tm-ok';
            resultNode.textContent =
                `${added.length} added, ${existing.length} already member, ${failed.length} failed.`;

            if (!failed.length) {
                clearSelectionState('Bulk add completed');
            }
        } catch (error) {
            panelLog(`ERROR: ${String(error?.message || error)}`);

            const resultNode = panel.querySelector('[data-role="result"]');
            resultNode.className = 'tm-error';
            resultNode.textContent = String(error?.message || error);
        } finally {
            running = false;
            updateExecuteButton(members);
        }
    }

    function openPanel(members) {
        closePanel();
        ensureStyle();

        selectedTargetGroup = null;
        currentSearchResults = [];

        panel = document.createElement('div');
        panel.id = PANEL_ID;

        panel.innerHTML = `
            <div class="tm-head">
                <span>Add selected members to another group</span>
                <button type="button" data-role="close">×</button>
            </div>
            <div class="tm-body">
                <div class="tm-selected">
                    <strong data-role="selection-count"></strong>
                    <div class="tm-muted">
                        Manual selections use the row checkbox state. Logical Select All uses Graph.
                    </div>
                </div>

                <div class="tm-row">
                    <input data-role="search-input"
                           type="text"
                           placeholder="Search target group by name"
                           autocomplete="off">
                    <button data-role="search-button" type="button">Search</button>
                </div>

                <div data-role="search-status"
                     class="tm-muted"
                     style="margin-top:6px;"></div>

                <div data-role="results"
                     class="tm-results"
                     style="display:none;"></div>

                <div data-role="target"
                     class="tm-muted"
                     style="margin-top:10px;">
                    Target: not selected
                </div>

                <div data-role="result"
                     class="tm-muted"
                     style="margin-top:5px;"></div>

                <div data-role="log" class="tm-log"></div>
            </div>

            <div class="tm-footer">
                <span class="tm-muted">
                    Uses the existing Entra/Intune Graph session token in memory only.
                </span>
                <div class="tm-row">
                    <button type="button" data-role="cancel">Cancel</button>
                    <button type="button"
                            data-role="execute"
                            class="primary"
                            disabled>
                        Select a target group
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(panel);

        const close = () => {
            if (!running) closePanel();
        };

        panel.querySelector('[data-role="close"]').addEventListener('click', close);
        panel.querySelector('[data-role="cancel"]').addEventListener('click', close);

        const searchInput = panel.querySelector('[data-role="search-input"]');
        const searchButton = panel.querySelector('[data-role="search-button"]');
        const status = panel.querySelector('[data-role="search-status"]');
        const results = panel.querySelector('[data-role="results"]');

        const doSearch = async () => {
            const query = searchInput.value.trim();

            selectedTargetGroup = null;
            updateExecuteButton(members);

            status.textContent = 'Searching...';
            results.style.display = '';
            results.replaceChildren();

            try {
                currentSearchResults = await searchGroups(query, members);
                status.textContent =
                    `${currentSearchResults.length} group${currentSearchResults.length === 1 ? '' : 's'} found.`;

                renderTargetResults(members);
            } catch (error) {
                currentSearchResults = [];
                results.style.display = 'none';
                status.textContent = '';

                const resultNode = panel.querySelector('[data-role="result"]');
                resultNode.className = 'tm-error';
                resultNode.textContent = String(error?.message || error);
            }
        };

        searchButton.addEventListener('click', doSearch);

        searchInput.addEventListener('keydown', event => {
            if (event.key === 'Enter') doSearch();
        });

        panel.querySelector('[data-role="execute"]').addEventListener(
            'click',
            () => executeAdd(members)
        );

        updateSelectionBadge();
        updateExecuteButton(members);

        panelLog(
            `Prepared ${members.length} selected member(s): ` +
            members.map(m => `${m.objectType}:${m.displayName}`).join(', ')
        );

        searchInput.focus();
    }

    function closePanel() {
        panel?.remove();
        panel = null;
        selectedTargetGroup = null;
        currentSearchResults = [];
    }

    function initialize() {
        try {
            document.documentElement.dataset.tmSelectedMembersToGroupV6 = 'active';
        } catch {}

        console.info('[Selected -> Group] Userscript loaded.', {
            version: VERSION,
            href: location.href,
            frameName: window.name || '(empty)'
        });

        installSelectionTracking();
        installSelectAllTracking();

        const observer = new MutationObserver(() => {
            bindBulkOperations();

            const button = getBulkOperationsButton();
            if (button?.getAttribute('aria-expanded') === 'true') {
                injectMenuItem(getBulkMenu(button));
            }
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });

        setInterval(() => {
            bindBulkOperations();
            syncVisibleSelection();

            const button = getBulkOperationsButton();
            if (button?.getAttribute('aria-expanded') === 'true') {
                injectMenuItem(getBulkMenu(button));
            }
        }, 750);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, { once: true });
    } else {
        initialize();
    }
})();
