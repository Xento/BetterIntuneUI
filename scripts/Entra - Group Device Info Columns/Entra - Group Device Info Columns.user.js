// ==UserScript==
// @name         Entra - Group Device Info Columns
// @namespace    xento.betterintuneui
// @version      5.0.0
// @description  Adds Entra/Intune/Autopilot device information to group member tables.
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
    const VERSION = '5.0.0';
    const SCRIPT_ID = 'tm-entra-group-device-info-v5';
    const CELL_CLASS = SCRIPT_ID + '-cell';
    const HEADER_CLASS = SCRIPT_ID + '-header';
    const SIZER_CLASS = SCRIPT_ID + '-sizer';
    const DROP_HINT_CLASS = SCRIPT_ID + '-drop-hint';

    const CFG = {
        directoryCacheMinutes: 10,
        autopilotCacheMinutes: 15,
        loadOwner: true,
        batchSize: 20,
        requestDebounceMs: 80,

        // Automatically size Microsoft's native Name column after the member
        // table has rendered. Preferred behavior is the same native action as
        // double-clicking the Name column separator.
        autoSizeNameColumn: true,

        // Run once shortly after rows are available, and once again after the
        // portal had time to finish its initial render.
        autoSizeNameDelaysMs: [250, 900],

        // Used only if Fluent's native double-click resize does not change the
        // width in this portal version.
        autoSizeNameFallbackMinWidth: 160,
        autoSizeNameFallbackMaxWidth: 520,
        autoSizeNameFallbackPadding: 44,

        // Native Microsoft column cleanup / ordering.
        //
        // Type is redundant because the icon already identifies the object.
        hideNativeColumns: [
            'objectType'
        ],

        // Hide these COMPLETE columns when the currently observed table is
        // device-only. If a User/Group row is ever observed in the same grid,
        // the native columns are restored automatically.
        hideNativeColumnsOnDeviceOnlyTables: [
            'mail',
            'userType'
        ],

        // In mixed tables, keep User-specific columns for User rows but blank
        // their Device-row cells so the shared column alignment stays intact.
        blankNativeColumnsForDevices: [
            'mail',
            'userType'
        ],

        // Move these native columns physically behind ALL custom enrichment
        // columns. Final order: Device ID -> Object ID.
        moveNativeColumnsToEnd: [
            'deviceId',
            'id'
        ],

        columns: [
            { key: 'enabled',          label: 'Enabled',         width: 82,  enabled: true  },
            { key: 'joinType',         label: 'Join type',       width: 145, enabled: true  },
            { key: 'compliant',        label: 'Compliant',       width: 92,  enabled: true  },
            { key: 'managed',          label: 'Managed',         width: 88,  enabled: true  },
            { key: 'mdm',              label: 'MDM',             width: 120, enabled: true  },
            { key: 'activity',         label: 'Activity',        width: 145, enabled: true  },
            { key: 'registered',       label: 'Registered',      width: 145, enabled: true  },
            { key: 'os',               label: 'OS / Version',    width: 185, enabled: true  },
            { key: 'autopilot',        label: 'Autopilot',       width: 92,  enabled: true  },
            { key: 'groupTag',         label: 'Group Tag',       width: 130, enabled: true  },
            { key: 'autopilotState',   label: 'AP state',        width: 105, enabled: true  },
            { key: 'autopilotContact', label: 'AP last contact', width: 145, enabled: true  },
            { key: 'model',            label: 'Model',           width: 165, enabled: true  },
            { key: 'owner',            label: 'Owner',           width: 210, enabled: true  },
            { key: 'serialNumber',     label: 'Serial number',   width: 140, enabled: false }
        ]
    };

    let graphAuthorization = null;
    let requestTimer = null;
    let requestRunning = false;
    let scanQueued = false;

    const autoSizedNameGrids = new WeakSet();
    const pendingNameAutoSizeTimers = new WeakMap();
    let autopilotPermissionWarningShown = false;
    let directoryPermissionWarningShown = false;

    const directoryCache = new Map();
    const ownerCache = new Map();
    const autopilotCache = new Map();
    const pendingDirectory = new Map();
    const runtimeColumnWidths = new Map();

    // Once a non-Device object was observed in a grid, never classify that grid
    // as device-only again. This avoids hiding User columns while Fluent
    // virtualizes mixed member lists.
    const gridsWithObservedNonDevice = new WeakSet();

    const enabledColumns = () => CFG.columns.filter(c => c.enabled);
    const now = () => Date.now();
    const normalize = v => String(v ?? '').trim().toLowerCase();
    const looksLikeGuid = v => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v || '').trim());
    const cacheFresh = (entry, minutes) => !!entry && now() - entry.fetchedAt < minutes * 60000;

    function chunks(items, size) {
        const out = [];
        for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
        return out;
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
            if (typeof headers.get === 'function') return headers.get(name) || headers.get(wanted) || '';
        } catch {}
        if (Array.isArray(headers)) {
            for (const pair of headers) if (Array.isArray(pair) && normalize(pair[0]) === wanted) return String(pair[1] || '');
        }
        if (typeof headers === 'object') {
            for (const [key, value] of Object.entries(headers)) if (normalize(key) === wanted) return String(value || '');
        }
        return '';
    }

    function captureGraphAuthorization(url, headers) {
        if (!isGraphUrl(url)) return;
        const auth = getHeaderValue(headers, 'Authorization');
        if (/^Bearer\s+\S+/i.test(auth)) graphAuthorization = auth;
    }

    function installNetworkHooks() {
        try {
            const originalFetch = PAGE.fetch;
            if (typeof originalFetch === 'function' && !originalFetch.__tmGroupDeviceInfoWrapped) {
                const wrapped = async function (...args) {
                    const request = args[0];
                    const init = args[1] || {};
                    const url = typeof request === 'string' || request instanceof URL ? String(request) : request?.url || '';
                    if (isGraphUrl(url)) captureGraphAuthorization(url, init.headers || request?.headers || null);
                    return originalFetch.apply(this, args);
                };
                Object.defineProperty(wrapped, '__tmGroupDeviceInfoWrapped', { value: true });
                PAGE.fetch = wrapped;
            }
        } catch (error) {
            console.warn('[Device Info Columns] fetch hook failed:', error);
        }

        try {
            const XHR = PAGE.XMLHttpRequest;
            if (!XHR || XHR.prototype.__tmGroupDeviceInfoWrapped) return;
            const originalOpen = XHR.prototype.open;
            const originalSend = XHR.prototype.send;
            const originalSetHeader = XHR.prototype.setRequestHeader;

            XHR.prototype.open = function (method, url, ...rest) {
                this.__tmGroupDeviceInfoUrl = String(url || '');
                this.__tmGroupDeviceInfoHeaders = {};
                return originalOpen.call(this, method, url, ...rest);
            };
            XHR.prototype.setRequestHeader = function (name, value) {
                this.__tmGroupDeviceInfoHeaders ||= {};
                this.__tmGroupDeviceInfoHeaders[name] = value;
                return originalSetHeader.call(this, name, value);
            };
            XHR.prototype.send = function (...args) {
                const url = this.__tmGroupDeviceInfoUrl || '';
                if (isGraphUrl(url)) captureGraphAuthorization(url, this.__tmGroupDeviceInfoHeaders || {});
                return originalSend.apply(this, args);
            };
            Object.defineProperty(XHR.prototype, '__tmGroupDeviceInfoWrapped', { value: true });
        } catch (error) {
            console.warn('[Device Info Columns] XHR hook failed:', error);
        }
    }

    installNetworkHooks();

    function graphHeaders(extra = {}) {
        if (!graphAuthorization) throw new Error('Graph token has not yet been captured from the current portal session.');
        return { Accept: 'application/json', Authorization: graphAuthorization, ...extra };
    }

    async function graphFetch(url, options = {}) {
        return PAGE.fetch(url, {
            ...options,
            headers: { ...graphHeaders(), ...(options.headers || {}) }
        });
    }

    async function sendBatch(requests) {
        const response = await graphFetch('https://graph.microsoft.com/v1.0/$batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ requests })
        });
        if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(`Graph batch failed: HTTP ${response.status}${text ? ` - ${text.slice(0, 250)}` : ''}`);
        }
        return response.json();
    }

    function cellText(row, key) {
        return String(row.querySelector(`[data-automationid="DetailsRowCell"][data-automation-key="${key}"]`)?.textContent || '').trim();
    }

    function rowInfo(row) {
        const objectType = cellText(row, 'objectType');
        const objectId = cellText(row, 'id');
        const deviceId = cellText(row, 'deviceId');
        return {
            objectType,
            objectId,
            deviceId,
            isDevice: normalize(objectType) === 'device' && looksLikeGuid(objectId) && looksLikeGuid(deviceId)
        };
    }

    function findMemberGrids() {
        return [...document.querySelectorAll('[role="grid"][aria-colcount]')].filter(grid =>
            grid.querySelector('[role="columnheader"][data-item-key="deviceId"]') &&
            grid.querySelector('[role="columnheader"][data-item-key="id"]')
        );
    }

    function stripIds(root) {
        for (const el of [root, ...root.querySelectorAll('*')]) {
            el.removeAttribute?.('id');
            el.removeAttribute?.('aria-labelledby');
            el.removeAttribute?.('aria-describedby');
            el.removeAttribute?.('data-focuszone-id');
        }
    }

    function nativeHeader(grid, key) {
        return grid.querySelector(
            `[role="columnheader"][data-item-key="${key}"]`
        );
    }

    function nativeRowCell(row, key) {
        return row.querySelector(
            `[data-automationid="DetailsRowCell"][data-automation-key="${key}"]`
        );
    }

    function isHeaderDropHint(element) {
        return !!element && (
            element.id?.startsWith('columnDropHint_') ||
            [...element.classList].some(name => name.startsWith('dropHintStyle-'))
        );
    }

    function isHeaderSizer(element) {
        return !!element && element.classList?.contains('ms-DetailsHeader-cellSizer');
    }

    function headerArtifacts(header) {
        if (!header) {
            return {
                dropHint: null,
                header: null,
                sizer: null
            };
        }

        const previous = header.previousElementSibling;
        const next = header.nextElementSibling;

        return {
            dropHint: isHeaderDropHint(previous) ? previous : null,
            header,
            sizer: isHeaderSizer(next) ? next : null
        };
    }

    function setHeaderGroupVisible(grid, key, visible) {
        const artifacts = headerArtifacts(nativeHeader(grid, key));

        for (const element of [
            artifacts.dropHint,
            artifacts.header,
            artifacts.sizer
        ]) {
            if (!element) continue;

            element.style.display = visible ? '' : 'none';

            if (visible) {
                element.removeAttribute('aria-hidden');
                delete element.dataset.tmNativeColumnHidden;
            } else {
                element.setAttribute('aria-hidden', 'true');
                element.dataset.tmNativeColumnHidden = '1';
            }
        }
    }

    function applyNativeHeaderCleanup(grid, deviceOnly) {
        // Always hidden.
        for (const key of CFG.hideNativeColumns || []) {
            setHeaderGroupVisible(grid, key, false);
        }

        // Hidden only for pure Device lists.
        for (const key of CFG.hideNativeColumnsOnDeviceOnlyTables || []) {
            setHeaderGroupVisible(grid, key, !deviceOnly);
        }
    }

    function applyNativeRowCleanup(row, isDevice, deviceOnly) {
        for (const key of CFG.hideNativeColumns || []) {
            const cell = nativeRowCell(row, key);
            if (!cell) continue;

            cell.style.display = 'none';
            cell.style.visibility = '';
            cell.setAttribute('aria-hidden', 'true');
            cell.dataset.tmNativeColumnHidden = '1';
        }

        for (const key of CFG.hideNativeColumnsOnDeviceOnlyTables || []) {
            const cell = nativeRowCell(row, key);
            if (!cell) continue;

            if (deviceOnly) {
                cell.style.display = 'none';
                cell.style.visibility = '';
                cell.setAttribute('aria-hidden', 'true');
                cell.dataset.tmNativeColumnHidden = '1';
            } else {
                cell.style.display = '';
                delete cell.dataset.tmNativeColumnHidden;

                if (isDevice) {
                    // In mixed lists the header/column must remain for Users, so
                    // only hide the Device value while preserving width.
                    cell.style.visibility = 'hidden';
                    cell.setAttribute('aria-hidden', 'true');
                    cell.dataset.tmBlankForDevice = '1';
                } else {
                    cell.style.visibility = '';
                    cell.removeAttribute('aria-hidden');
                    delete cell.dataset.tmBlankForDevice;
                }
            }
        }
    }

    function moveNativeHeaderGroupToEnd(grid, key) {
        const header = nativeHeader(grid, key);
        const headerRow = grid.querySelector('.ms-DetailsHeader[role="row"]');

        if (!header || !headerRow || header.parentElement !== headerRow) {
            return;
        }

        const artifacts = headerArtifacts(header);

        // Clear v2 CSS-order values. We now move the actual Fluent DOM group.
        for (const element of [
            artifacts.dropHint,
            artifacts.header,
            artifacts.sizer
        ]) {
            if (element) element.style.order = '';
        }

        // Preserve Fluent's internal visual group:
        //   drop hint -> column header -> column sizer
        //
        // Appending moves Device ID / Object ID after all custom headers and
        // keeps their own resize/drop helper next to the correct header.
        if (artifacts.dropHint) headerRow.appendChild(artifacts.dropHint);
        headerRow.appendChild(artifacts.header);
        if (artifacts.sizer) headerRow.appendChild(artifacts.sizer);
    }

    function moveNativeHeadersToEnd(grid) {
        for (const key of CFG.moveNativeColumnsToEnd || []) {
            moveNativeHeaderGroupToEnd(grid, key);
        }
    }

    function moveNativeRowCellsToEnd(row) {
        const fields = row.querySelector(
            '[data-automationid="DetailsRowFields"]'
        );

        if (!fields) return;

        for (const key of CFG.moveNativeColumnsToEnd || []) {
            const cell = nativeRowCell(row, key);
            if (!cell || cell.parentElement !== fields) continue;

            cell.style.order = '';
            fields.appendChild(cell);
        }
    }

    function gridIsDeviceOnly(grid, rows) {
        for (const row of rows) {
            const type = normalize(cellText(row, 'objectType'));

            if (type && type !== 'device') {
                gridsWithObservedNonDevice.add(grid);
                break;
            }
        }

        return rows.length > 0 && !gridsWithObservedNonDevice.has(grid);
    }

    function customColumnWidth(column) {
        return runtimeColumnWidths.get(column.key) || column.width;
    }

    function recalculateGridWidth(grid) {
        const headerRow = grid.querySelector('.ms-DetailsHeader[role="row"]');
        if (!headerRow) return;

        const visibleHeaders = [...headerRow.querySelectorAll('[role="columnheader"]')]
            .filter(header => header.style.display !== 'none');

        let width = 48;
        for (const header of visibleHeaders) {
            width += parseFloat(header.style.width || '0') ||
                header.getBoundingClientRect().width || 120;
        }

        grid.setAttribute('aria-colcount', String(visibleHeaders.length));
        grid.style.minWidth = `${Math.ceil(width + 20)}px`;
    }

    function applyCustomColumnWidth(grid, columnKey, width) {
        runtimeColumnWidths.set(columnKey, width);

        const header = grid.querySelector(
            `[role="columnheader"][data-item-key="${SCRIPT_ID}-${columnKey}"]`
        );

        if (header) {
            header.style.width = `${width}px`;
            header.style.minWidth = `${width}px`;
            header.style.maxWidth = `${width}px`;
        }

        for (const row of grid.querySelectorAll(
            '[role="row"][data-automationid="DetailsRow"]'
        )) {
            const cell = row.querySelector(
                `[data-automationid="DetailsRowCell"]` +
                `[data-automation-key="${SCRIPT_ID}-${columnKey}"]`
            );
            if (!cell) continue;

            cell.style.width = `${width}px`;
            cell.style.minWidth = `${width}px`;
            cell.style.maxWidth = `${width}px`;
        }

        recalculateGridWidth(grid);
    }

    function bindCustomSizer(grid, header, sizer, column) {
        if (!sizer || sizer.dataset.tmResizeBound === '1') return;

        sizer.dataset.tmResizeBound = '1';
        sizer.dataset.tmColumnKey = column.key;
        sizer.style.display = '';
        sizer.style.cursor = 'col-resize';
        sizer.style.touchAction = 'none';
        sizer.setAttribute('role', 'separator');
        sizer.setAttribute('aria-orientation', 'vertical');

        sizer.addEventListener('pointerdown', event => {
            if (event.button !== 0) return;

            event.preventDefault();
            event.stopPropagation();

            const startX = event.clientX;
            const startWidth = customColumnWidth(column);
            const minWidth = 55;
            const maxWidth = 600;

            const onMove = moveEvent => {
                const width = Math.max(
                    minWidth,
                    Math.min(
                        maxWidth,
                        Math.round(startWidth + moveEvent.clientX - startX)
                    )
                );
                applyCustomColumnWidth(grid, column.key, width);
            };

            const onUp = () => {
                window.removeEventListener('pointermove', onMove, true);
                window.removeEventListener('pointerup', onUp, true);
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            };

            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
            window.addEventListener('pointermove', onMove, true);
            window.addEventListener('pointerup', onUp, true);
        }, true);
    }

    function createCustomSizer(grid, referenceSizer, header, column) {
        const sizer = referenceSizer
            ? referenceSizer.cloneNode(true)
            : document.createElement('div');

        stripIds(sizer);
        sizer.classList.add('ms-DetailsHeader-cellSizer', SIZER_CLASS);
        sizer.dataset.tmColumnKey = column.key;
        sizer.removeAttribute('data-is-focusable');
        sizer.removeAttribute('tabindex');
        sizer.removeAttribute('aria-labelledby');
        sizer.removeAttribute('aria-describedby');
        sizer.style.display = '';

        bindCustomSizer(grid, header, sizer, column);
        return sizer;
    }

    function createCustomDropHint(referenceDropHint, column) {
        const hint = referenceDropHint
            ? referenceDropHint.cloneNode(true)
            : document.createElement('div');

        stripIds(hint);
        hint.classList.add(DROP_HINT_CLASS);
        hint.dataset.tmColumnKey = column.key;
        hint.style.display = 'none';
        return hint;
    }

    function ensureHeaderColumns(grid, deviceOnly) {
        applyNativeHeaderCleanup(grid, deviceOnly);

        const headerRow = grid.querySelector('.ms-DetailsHeader[role="row"]');
        if (!headerRow) return;

        const ref =
            headerRow.querySelector('[role="columnheader"][data-item-key="deviceId"]') ||
            headerRow.querySelector('[role="columnheader"]');
        if (!ref) return;

        const refArtifacts = headerArtifacts(ref);

        for (const column of enabledColumns()) {
            const key = `${SCRIPT_ID}-${column.key}`;
            let header = headerRow.querySelector(
                `[role="columnheader"][data-item-key="${key}"]`
            );

            if (!header) {
                header = ref.cloneNode(true);
                stripIds(header);
                header.classList.add(HEADER_CLASS);
                header.setAttribute('data-item-key', key);
                header.setAttribute('aria-sort', 'none');
                header.setAttribute('draggable', 'false');
                header.removeAttribute('data-is-draggable');

                const width = customColumnWidth(column);
                header.style.width = header.style.minWidth = header.style.maxWidth = `${width}px`;

                header.querySelectorAll('i').forEach(icon => icon.remove());

                const name =
                    header.querySelector('.ms-DetailsHeader-cellName') ||
                    header.querySelector('span');
                if (name) {
                    name.textContent = column.label;
                    name.removeAttribute('id');
                } else {
                    header.textContent = column.label;
                }

                const title = header.querySelector('.ms-DetailsHeader-cellTitle');
                if (title) {
                    title.removeAttribute('role');
                    title.removeAttribute('tabindex');
                    title.removeAttribute('data-is-focusable');
                    title.removeAttribute('aria-labelledby');
                    title.removeAttribute('aria-describedby');
                }

                const dropHint = createCustomDropHint(
                    refArtifacts.dropHint,
                    column
                );
                const sizer = createCustomSizer(
                    grid,
                    refArtifacts.sizer,
                    header,
                    column
                );

                // Same visual structure as Fluent native columns:
                // drop hint -> header -> resize separator.
                headerRow.appendChild(dropHint);
                headerRow.appendChild(header);
                headerRow.appendChild(sizer);
            } else {
                const width = customColumnWidth(column);
                header.style.width = header.style.minWidth = header.style.maxWidth = `${width}px`;

                let sizer = header.nextElementSibling;
                if (!isHeaderSizer(sizer) || !sizer.classList.contains(SIZER_CLASS)) {
                    sizer = createCustomSizer(
                        grid,
                        refArtifacts.sizer,
                        header,
                        column
                    );
                    header.insertAdjacentElement('afterend', sizer);
                } else {
                    bindCustomSizer(grid, header, sizer, column);
                }
            }
        }

        moveNativeHeadersToEnd(grid);
        recalculateGridWidth(grid);
    }

    function createInfoCell(ref, column) {
        const cell = ref.cloneNode(false);
        stripIds(cell);
        cell.classList.add(CELL_CLASS);
        cell.setAttribute('data-automationid', 'DetailsRowCell');
        cell.setAttribute('data-automation-key', `${SCRIPT_ID}-${column.key}`);
        const width = customColumnWidth(column);
        cell.style.width = cell.style.minWidth = cell.style.maxWidth = `${width}px`;
        cell.style.overflow = 'hidden';
        cell.style.textOverflow = 'ellipsis';
        cell.style.whiteSpace = 'nowrap';
        const span = document.createElement('span');
        span.dataset.tmValue = '1';
        span.textContent = '…';
        span.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;width:100%;';
        cell.appendChild(span);
        return cell;
    }

    function ensureRowColumns(row) {
        const fields = row.querySelector('[data-automationid="DetailsRowFields"]');
        if (!fields) return;
        const ref = fields.querySelector('[data-automationid="DetailsRowCell"][data-automation-key="deviceId"]') || fields.querySelector('[data-automationid="DetailsRowCell"]');
        if (!ref) return;
        for (const column of enabledColumns()) {
            const key = `${SCRIPT_ID}-${column.key}`;
            if (!fields.querySelector(`[data-automationid="DetailsRowCell"][data-automation-key="${key}"]`)) {
                fields.appendChild(createInfoCell(ref, column));
            }
        }
    }

    function getCustomCell(row, key) {
        return row.querySelector(`[data-automationid="DetailsRowCell"][data-automation-key="${SCRIPT_ID}-${key}"]`);
    }

    function setCell(row, key, value, options = {}) {
        const cell = getCustomCell(row, key);
        if (!cell) return;
        const span = cell.querySelector('[data-tm-value="1"]') || cell;
        const next = value === null || value === undefined || value === '' ? '—' : String(value);
        if (span.textContent !== next) span.textContent = next;
        cell.title = options.title || (next !== '—' ? next : '');
        span.style.color = options.kind === 'good'
            ? 'var(--colorTextSuccess,#107c10)'
            : options.kind === 'bad'
                ? 'var(--colorTextError,#d13438)'
                : options.kind === 'warn'
                    ? 'var(--colorTextWarning,#c19c00)'
                    : '';
    }

    function setAll(row, value) {
        for (const column of enabledColumns()) setCell(row, column.key, value);
    }

    function formatDateTime(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return new Intl.DateTimeFormat(undefined, {
            year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
        }).format(date);
    }

    function joinType(value) {
        switch (normalize(value)) {
            case 'azuread': return 'Entra joined';
            case 'serverad': return 'Hybrid joined';
            case 'workplace': return 'Entra registered';
            default: return value || 'Unknown';
        }
    }

    function boolText(value) {
        return value === true ? 'Yes' : value === false ? 'No' : '—';
    }

    function mdmText(device) {
        const appId = normalize(device?.mdmAppId);
        if (appId === '0000000a-0000-0000-c000-000000000000') return 'Intune';
        if (appId === '54b943f8-d761-4f8d-951e-9cea1846db5a') return 'ConfigMgr co-mgmt';
        if (device?.managementType) return String(device.managementType);
        return device?.isManaged ? 'Managed' : 'None';
    }

    function physicalIdInfo(device) {
        const ids = Array.isArray(device?.physicalIds) ? device.physicalIds.map(String) : [];
        const autopilot = ids.some(value => normalize(value).startsWith('[ztdid]'));
        let groupTag = '';
        for (const value of ids) {
            const match = value.match(/^\[OrderID\]:(.*)$/i);
            if (match) { groupTag = match[1] || ''; break; }
        }
        return { autopilot, groupTag };
    }

    function osText(device) {
        const os = String(device?.operatingSystem || '').trim();
        const version = String(device?.operatingSystemVersion || '').trim();
        return os && version ? `${os} ${version}` : os || version || '—';
    }

    function modelText(device) {
        const manufacturer = String(device?.manufacturer || '').trim();
        const model = String(device?.model || '').trim();
        if (manufacturer && model) return normalize(model).startsWith(normalize(manufacturer)) ? model : `${manufacturer} ${model}`;
        return model || manufacturer || '—';
    }

    const DIRECTORY_SELECT = [
        'id','deviceId','displayName','accountEnabled','trustType','isCompliant','isManaged',
        'managementType','mdmAppId','operatingSystem','operatingSystemVersion','registrationDateTime',
        'approximateLastSignInDateTime','profileType','manufacturer','model','deviceOwnership',
        'enrollmentType','enrollmentProfileName','physicalIds'
    ].join(',');

    function queueDirectoryLoad(info) {
        const cached = directoryCache.get(normalize(info.objectId));
        if (!cacheFresh(cached, CFG.directoryCacheMinutes)) {
            pendingDirectory.set(normalize(info.objectId), { objectId: info.objectId, deviceId: info.deviceId });
        }
        scheduleFlush();
    }

    function scheduleFlush() {
        if (requestTimer || !pendingDirectory.size) return;
        requestTimer = setTimeout(() => {
            requestTimer = null;
            flushRequests();
        }, CFG.requestDebounceMs);
    }

    async function loadDirectoryBatch(items) {
        const map = new Map();
        const requests = items.map((item, index) => {
            const id = String(index + 1);
            map.set(id, item);
            return { id, method: 'GET', url: `/devices/${encodeURIComponent(item.objectId)}?$select=${encodeURIComponent(DIRECTORY_SELECT)}` };
        });
        const body = await sendBatch(requests);
        for (const response of body.responses || []) {
            const item = map.get(String(response.id));
            if (!item) continue;
            if (response.status >= 200 && response.status < 300) {
                directoryCache.set(normalize(item.objectId), { fetchedAt: now(), data: response.body, error: null });
            } else {
                const error = response.body?.error?.message || `HTTP ${response.status}`;
                directoryCache.set(normalize(item.objectId), { fetchedAt: now(), data: null, error });
                if (response.status === 403 && !directoryPermissionWarningShown) {
                    directoryPermissionWarningShown = true;
                    console.warn('[Device Info Columns] Directory lookup returned 403:', error);
                }
            }
        }
    }

    async function loadOwnerBatch(items) {
        const map = new Map();
        const requests = items.map((item, index) => {
            const id = String(index + 1);
            map.set(id, item);
            return {
                id,
                method: 'GET',
                url: `/devices/${encodeURIComponent(item.objectId)}/registeredOwners/microsoft.graph.user?$select=id,displayName,userPrincipalName&$top=3`
            };
        });
        try {
            const body = await sendBatch(requests);
            for (const response of body.responses || []) {
                const item = map.get(String(response.id));
                if (!item) continue;
                ownerCache.set(normalize(item.objectId), {
                    fetchedAt: now(),
                    data: response.status >= 200 && response.status < 300 && Array.isArray(response.body?.value) ? response.body.value : [],
                    error: response.status >= 200 && response.status < 300 ? null : (response.body?.error?.message || `HTTP ${response.status}`)
                });
            }
        } catch (error) {
            for (const item of items) ownerCache.set(normalize(item.objectId), { fetchedAt: now(), data: [], error: String(error?.message || error) });
        }
    }

    async function loadAutopilotBatch(items) {
        const AP_SELECT = [
            'id','groupTag','serialNumber','manufacturer','model','enrollmentState','lastContactedDateTime',
            'azureActiveDirectoryDeviceId','managedDeviceId','displayName'
        ].join(',');
        const map = new Map();
        const requests = items.map((item, index) => {
            const id = String(index + 1);
            map.set(id, item);
            const filter = `azureActiveDirectoryDeviceId eq '${item.deviceId.replaceAll("'", "''")}'`;
            return {
                id,
                method: 'GET',
                url: `/deviceManagement/windowsAutopilotDeviceIdentities?$filter=${encodeURIComponent(filter)}&$select=${encodeURIComponent(AP_SELECT)}&$top=2`
            };
        });
        try {
            const body = await sendBatch(requests);
            for (const response of body.responses || []) {
                const item = map.get(String(response.id));
                if (!item) continue;
                if (response.status >= 200 && response.status < 300) {
                    const values = Array.isArray(response.body?.value) ? response.body.value : [];
                    autopilotCache.set(normalize(item.deviceId), { fetchedAt: now(), data: values[0] || null, error: null });
                } else {
                    const error = response.body?.error?.message || `HTTP ${response.status}`;
                    autopilotCache.set(normalize(item.deviceId), { fetchedAt: now(), data: null, error });
                    if (response.status === 403 && !autopilotPermissionWarningShown) {
                        autopilotPermissionWarningShown = true;
                        console.warn('[Device Info Columns] Autopilot lookup returned 403. Basic detection still works via physicalIds:', error);
                    }
                }
            }
        } catch (error) {
            for (const item of items) autopilotCache.set(normalize(item.deviceId), { fetchedAt: now(), data: null, error: String(error?.message || error) });
        }
    }

    async function flushRequests() {
        if (requestRunning || !graphAuthorization || !pendingDirectory.size) return;
        requestRunning = true;
        try {
            const items = [...pendingDirectory.values()];
            pendingDirectory.clear();
            for (const group of chunks(items, CFG.batchSize)) await loadDirectoryBatch(group);

            if (CFG.loadOwner) {
                const owners = items.filter(item => !cacheFresh(ownerCache.get(normalize(item.objectId)), CFG.directoryCacheMinutes));
                for (const group of chunks(owners, CFG.batchSize)) await loadOwnerBatch(group);
            }

            const apItems = items.filter(item => {
                const device = directoryCache.get(normalize(item.objectId))?.data;
                return physicalIdInfo(device).autopilot && !cacheFresh(autopilotCache.get(normalize(item.deviceId)), CFG.autopilotCacheMinutes);
            });
            for (const group of chunks(apItems, CFG.batchSize)) await loadAutopilotBatch(group);
        } catch (error) {
            console.error('[Device Info Columns] Data load failed:', error);
        } finally {
            requestRunning = false;
            queueScan();
            if (pendingDirectory.size) scheduleFlush();
        }
    }

    function renderDeviceRow(row, info) {
        const entry = directoryCache.get(normalize(info.objectId));
        if (!entry) {
            setAll(row, '…');
            queueDirectoryLoad(info);
            return;
        }
        if (entry.error || !entry.data) {
            setAll(row, 'Error');
            return;
        }

        const d = entry.data;
        const p = physicalIdInfo(d);
        const apEntry = autopilotCache.get(normalize(info.deviceId));
        const ap = apEntry?.data || null;
        const ownerEntry = ownerCache.get(normalize(info.objectId));

        setCell(row, 'enabled', boolText(d.accountEnabled), { kind: d.accountEnabled === true ? 'good' : d.accountEnabled === false ? 'bad' : '' });
        setCell(row, 'joinType', joinType(d.trustType));
        setCell(row, 'compliant', boolText(d.isCompliant), { kind: d.isCompliant === true ? 'good' : d.isCompliant === false ? 'bad' : '' });
        setCell(row, 'managed', boolText(d.isManaged), { kind: d.isManaged === true ? 'good' : d.isManaged === false ? 'warn' : '' });
        setCell(row, 'mdm', mdmText(d));
        setCell(row, 'activity', formatDateTime(d.approximateLastSignInDateTime));
        setCell(row, 'registered', formatDateTime(d.registrationDateTime));
        setCell(row, 'os', osText(d));
        setCell(row, 'autopilot', p.autopilot ? 'Yes' : 'No', { kind: p.autopilot ? 'good' : '' });
        setCell(row, 'groupTag', ap?.groupTag || p.groupTag || '—');
        setCell(row, 'model', modelText(d));

        if (!p.autopilot) {
            setCell(row, 'autopilotState', '—');
            setCell(row, 'autopilotContact', '—');
            setCell(row, 'serialNumber', '—');
        } else if (!apEntry) {
            setCell(row, 'autopilotState', '…');
            setCell(row, 'autopilotContact', '…');
            setCell(row, 'serialNumber', '…');
        } else if (apEntry.error) {
            setCell(row, 'autopilotState', 'Unavailable', { title: apEntry.error });
            setCell(row, 'autopilotContact', '—');
            setCell(row, 'serialNumber', '—');
        } else {
            setCell(row, 'autopilotState', ap?.enrollmentState || '—');
            setCell(row, 'autopilotContact', formatDateTime(ap?.lastContactedDateTime));
            setCell(row, 'serialNumber', ap?.serialNumber || '—');
        }

        if (!CFG.loadOwner) {
            setCell(row, 'owner', 'Disabled');
        } else if (!ownerEntry) {
            setCell(row, 'owner', '…');
        } else if (ownerEntry.error) {
            setCell(row, 'owner', 'Unavailable', { title: ownerEntry.error });
        } else {
            const text = (ownerEntry.data || []).map(o => o.userPrincipalName || o.displayName || '').filter(Boolean).join(', ');
            setCell(row, 'owner', text || '—');
        }
    }

    function enrichRow(row, deviceOnly) {
        ensureRowColumns(row);
        const info = rowInfo(row);

        // Fluent recycles row DOM while scrolling, therefore re-apply native
        // cleanup/order on every pass.
        applyNativeRowCleanup(row, info.isDevice, deviceOnly);
        moveNativeRowCellsToEnd(row);

        if (!info.isDevice) {
            setAll(row, '—');
            return;
        }
        renderDeviceRow(row, info);
        const dirFresh = cacheFresh(directoryCache.get(normalize(info.objectId)), CFG.directoryCacheMinutes);
        const ownerFresh = !CFG.loadOwner || cacheFresh(ownerCache.get(normalize(info.objectId)), CFG.directoryCacheMinutes);
        const d = directoryCache.get(normalize(info.objectId))?.data;
        const p = physicalIdInfo(d);
        const apFresh = !p.autopilot || cacheFresh(autopilotCache.get(normalize(info.deviceId)), CFG.autopilotCacheMinutes);
        if (!dirFresh || !ownerFresh || !apFresh) queueDirectoryLoad(info);
    }


    function getNameHeader(grid) {
        return (
            grid.querySelector(
                '[role="columnheader"][data-item-key="displayName"]'
            ) ||
            grid.querySelector(
                '[role="columnheader"][data-item-key="name"]'
            )
        );
    }

    function getNativeSizerForHeader(header) {
        if (!header) return null;

        const next = header.nextElementSibling;

        if (
            next?.classList?.contains('ms-DetailsHeader-cellSizer')
        ) {
            return next;
        }

        // Fallback for portal versions that insert an extra element between
        // header and separator.
        let sibling = header.nextElementSibling;
        for (let i = 0; sibling && i < 3; i++, sibling = sibling.nextElementSibling) {
            if (sibling.classList?.contains('ms-DetailsHeader-cellSizer')) {
                return sibling;
            }
        }

        return null;
    }

    function measureTextWidth(text, referenceElement) {
        const canvas =
            measureTextWidth.canvas ||
            (measureTextWidth.canvas = document.createElement('canvas'));

        const context = canvas.getContext('2d');
        if (!context) return String(text || '').length * 8;

        const style = getComputedStyle(referenceElement || document.body);
        context.font = [
            style.fontStyle,
            style.fontVariant,
            style.fontWeight,
            style.fontSize,
            style.fontFamily
        ].filter(Boolean).join(' ');

        return context.measureText(String(text || '')).width;
    }

    function manuallySizeNameColumn(grid, header) {
        const rows = [
            ...grid.querySelectorAll(
                '[role="row"][data-automationid="DetailsRow"]'
            )
        ];

        const headerText =
            header.querySelector('.ms-DetailsHeader-cellName')?.textContent ||
            header.textContent ||
            'Name';

        let widest = measureTextWidth(headerText, header);

        for (const row of rows) {
            const cell =
                row.querySelector(
                    '[data-automationid="DetailsRowCell"][data-automation-key="displayName"]'
                ) ||
                row.querySelector(
                    '[data-automationid="DetailsRowCell"][data-automation-key="name"]'
                );

            if (!cell) continue;

            widest = Math.max(
                widest,
                measureTextWidth(cell.textContent || '', cell)
            );
        }

        const minWidth = Number(CFG.autoSizeNameFallbackMinWidth) || 160;
        const maxWidth = Number(CFG.autoSizeNameFallbackMaxWidth) || 520;
        const padding = Number(CFG.autoSizeNameFallbackPadding) || 44;

        const width = Math.max(
            minWidth,
            Math.min(maxWidth, Math.ceil(widest + padding))
        );

        header.style.width = `${width}px`;
        header.style.minWidth = `${width}px`;
        header.style.maxWidth = `${width}px`;

        for (const row of rows) {
            const cell =
                row.querySelector(
                    '[data-automationid="DetailsRowCell"][data-automation-key="displayName"]'
                ) ||
                row.querySelector(
                    '[data-automationid="DetailsRowCell"][data-automation-key="name"]'
                );

            if (!cell) continue;

            cell.style.width = `${width}px`;
            cell.style.minWidth = `${width}px`;
            cell.style.maxWidth = `${width}px`;
        }

        if (typeof recalculateGridWidth === 'function') {
            recalculateGridWidth(grid);
        }

        console.info(
            '[Device Info Columns] Name column manually auto-sized.',
            { width }
        );
    }

    function runNameColumnAutoSize(grid) {
        if (!CFG.autoSizeNameColumn || !grid || !document.contains(grid)) return;

        const rows = grid.querySelectorAll(
            '[role="row"][data-automationid="DetailsRow"]'
        );

        if (!rows.length) return;

        const header = getNameHeader(grid);
        if (!header) return;

        const sizer = getNativeSizerForHeader(header);
        const beforeWidth = header.getBoundingClientRect().width;

        if (sizer) {
            // This intentionally mirrors a user double-click on the native
            // Fluent separator. It preserves Microsoft's own sizing logic when
            // that handler is available in the current portal build.
            sizer.dispatchEvent(
                new MouseEvent('dblclick', {
                    bubbles: true,
                    cancelable: true,
                    view: window,
                    detail: 2,
                    button: 0,
                    buttons: 0
                })
            );
        }

        requestAnimationFrame(() => {
            const afterWidth = header.getBoundingClientRect().width;

            // If Fluent didn't react, use a deterministic content measurement
            // fallback based on the currently rendered member names.
            if (!sizer || Math.abs(afterWidth - beforeWidth) < 1) {
                manuallySizeNameColumn(grid, header);
            } else if (typeof recalculateGridWidth === 'function') {
                recalculateGridWidth(grid);
            }
        });
    }

    function scheduleNameColumnAutoSize(grid) {
        if (!CFG.autoSizeNameColumn || autoSizedNameGrids.has(grid)) return;

        const rows = grid.querySelectorAll(
            '[role="row"][data-automationid="DetailsRow"]'
        );

        if (!rows.length) return;

        autoSizedNameGrids.add(grid);

        const timers = [];

        for (const delay of CFG.autoSizeNameDelaysMs || [250, 900]) {
            const timer = setTimeout(() => {
                runNameColumnAutoSize(grid);
            }, Math.max(0, Number(delay) || 0));

            timers.push(timer);
        }

        pendingNameAutoSizeTimers.set(grid, timers);
    }

    function scan() {
        for (const grid of findMemberGrids()) {
            const rows = [
                ...grid.querySelectorAll(
                    '[role="row"][data-automationid="DetailsRow"]'
                )
            ];

            const deviceOnly = gridIsDeviceOnly(grid, rows);

            ensureHeaderColumns(grid, deviceOnly);

            scheduleNameColumnAutoSize(grid);

            for (const row of rows) {
                enrichRow(row, deviceOnly);
            }

            // Run the header move one more time after row/custom-column creation.
            // React can recreate native header children independently of rows.
            moveNativeHeadersToEnd(grid);
        }

        if (pendingDirectory.size && graphAuthorization) {
            scheduleFlush();
        }
    }

    function queueScan() {
        if (scanQueued) return;
        scanQueued = true;
        requestAnimationFrame(() => {
            scanQueued = false;
            scan();
        });
    }

    function installObserver() {
        const observer = new MutationObserver(mutations => {
            let relevant = false;
            for (const mutation of mutations) {
                const target = mutation.target instanceof Element ? mutation.target : mutation.target?.parentElement;
                if (target?.closest?.(`.${CELL_CLASS}, .${HEADER_CLASS}`)) continue;
                for (const node of mutation.addedNodes || []) {
                    if (!(node instanceof Element)) continue;
                    if (
                        node.matches?.('[role="row"][data-automationid="DetailsRow"], [role="grid"], .ms-DetailsHeader') ||
                        node.querySelector?.('[role="row"][data-automationid="DetailsRow"], [role="columnheader"][data-item-key="deviceId"]')
                    ) {
                        relevant = true;
                        break;
                    }
                }
                if (relevant) break;
            }
            if (relevant) queueScan();
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
    }

    function initialize() {
        try { document.documentElement.dataset.tmGroupDeviceInfoV5 = 'active'; } catch {}
        console.info('[Device Info Columns] Userscript loaded.', {
            version: VERSION,
            frameName: window.name || '(empty)',
            url: location.href,
            columns: enabledColumns().map(c => c.key)
        });
        installObserver();
        queueScan();
        setInterval(queueScan, 1000);
        setTimeout(() => {
            if (!graphAuthorization) {
                console.info('[Device Info Columns] Waiting for Graph token. If cells stay on "…", click the native Refresh button once.');
            }
        }, 5000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, { once: true });
    } else {
        initialize();
    }
})();
