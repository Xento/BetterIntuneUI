// ==UserScript==
// @name         Intune - Autopatch Calendar
// @namespace    xento.betterintuneui
// @version      0.7.0
// @description  Adds per-Autopatch-group and all-groups rollout calendars to Intune Windows Update rings. Uses Autopatch quality plans, driver-update profiles, and multi-phase feature-update releases from the Intune portal, plus actual Entra deployment-ring member counts.
// @author       Xento
// @match        https://intune.microsoft.com/*
// @match        https://*.reactblade.portal.azure.net/*
// @match        https://*.reactblade-ms.portal.azure.net/*
// @match        https://*.reactblade-rc.portal.azure.net/*
// @run-at       document-start
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      graph.microsoft.com
// @connect      services.autopatch.microsoft.com
// @connect      learn.microsoft.com
// ==/UserScript==

(() => {
    'use strict';

    const SCRIPT = 'Autopatch Calendar';
    const VERSION = '0.7.0';
    const KEY = {
        TOKENS: 'apcal.v2.tokens',
        CACHE: 'apcal.v2.cache',
        COUNTS: 'apcal.v2.deviceCounts',
        COUNT_OVERRIDES: 'apcal.v2.countOverrides',
        FEATURE_RELEASES: 'apcal.v2.featureReleases',
        SETTINGS: 'apcal.v2.settings'
    };

    const SETTINGS_DEFAULT = {
        featureVersion: '25H2',
        countCacheHours: 6,
        debug: false,
        featureReleaseSelection: 'auto'
    };

    const CACHE_NAMES = {
        POLICIES: 'wufbPolicies',
        QUALITY_SUMMARY: 'qualitySummary',
        QUALITY_CATALOG: 'qualityCatalog',
        FEATURE_PROFILES: 'featureProfiles',
        DRIVER_PROFILES: 'driverProfiles',
        FEATURE_RELEASES: 'featureReleaseSummary',
        FEATURE_COMPLETION: 'featureCompletion'
    };

    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    const settings = () => ({...SETTINGS_DEFAULT, ...(GM_getValue(KEY.SETTINGS, {}) || {})});
    const log = (...args) => { if (settings().debug) console.log(`[${SCRIPT} ${VERSION}]`, ...args); };

    function localDate(value) {
        if (!value) return null;
        if (value instanceof Date) return new Date(value.getTime());
        const s = String(value).trim();
        let m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
        if (m) return new Date(Number(m[3]), Number(m[1]) - 1, Number(m[2]), 12, 0, 0, 0);
        m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
        if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12, 0, 0, 0);
        const d = new Date(s);
        if (Number.isNaN(d.getTime())) return null;
        d.setHours(12,0,0,0);
        return d;
    }

    function isoDate(value) {
        const d = localDate(value);
        if (!d) return '';
        return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    }

    function addDays(value, days) {
        const d = localDate(value);
        if (!d) return null;
        d.setDate(d.getDate() + Number(days || 0));
        return d;
    }

    function sameMonth(a, b) {
        a = localDate(a); b = localDate(b);
        return !!a && !!b && a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth();
    }

    function monthLabel(d) {
        return d.toLocaleDateString(undefined, {month:'long', year:'numeric'});
    }

    function secondTuesday(year, month0) {
        const d = new Date(year, month0, 1, 12, 0, 0, 0);
        const offset = (2 - d.getDay() + 7) % 7;
        d.setDate(1 + offset + 7);
        return d;
    }

    function decodeJwt(token) {
        try {
            const p = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
            const pad = p + '='.repeat((4 - p.length % 4) % 4);
            const text = atob(pad);
            const bytes = Uint8Array.from(text, c => c.charCodeAt(0));
            return JSON.parse(new TextDecoder().decode(bytes));
        } catch { return null; }
    }

    function scopesFromJwt(p) {
        const out = new Set(String(p?.scp || '').split(/\s+/).filter(Boolean));
        for (const x of (p?.roles || [])) out.add(x);
        return [...out];
    }

    function saveBearer(token, url='') {
        if (!token || token.split('.').length < 3) return;
        const p = decodeJwt(token);
        if (!p || (p.exp && p.exp * 1000 < Date.now() + 60_000)) return;
        const all = GM_getValue(KEY.TOKENS, {}) || {};
        const target = /services\.autopatch\.microsoft\.com/i.test(url) ? 'autopatch' : /graph\.microsoft\.com/i.test(url) ? 'graph' : 'other';
        const id = `${target}:${p.oid || p.sub || 'user'}:${p.appid || p.azp || 'app'}:${p.aud || 'aud'}:${p.exp || 0}`;
        all[id] = {
            token,
            target,
            aud: String(p.aud || ''),
            exp: Number(p.exp || 0),
            scopes: scopesFromJwt(p),
            captured: Date.now()
        };
        for (const [k,v] of Object.entries(all)) if ((v.exp || 0) * 1000 < Date.now() + 10_000) delete all[k];
        GM_setValue(KEY.TOKENS, all);
    }

    function authFromHeaders(headers) {
        try {
            if (!headers) return null;
            if (headers instanceof Headers) return headers.get('authorization');
            if (Array.isArray(headers)) {
                const h = headers.find(([k]) => String(k).toLowerCase() === 'authorization');
                return h?.[1] || null;
            }
            for (const [k,v] of Object.entries(headers)) if (String(k).toLowerCase() === 'authorization') return v;
        } catch {}
        return null;
    }

    function getTokens(target) {
        const all = Object.values(GM_getValue(KEY.TOKENS, {}) || {});
        return all.filter(x => x.target === target && (x.exp || 0) * 1000 > Date.now() + 60_000).sort((a,b) => (b.captured || 0) - (a.captured || 0));
    }

    function tokenHasAny(tokenObj, scopes) {
        const set = new Set(tokenObj?.scopes || []);
        return scopes.some(x => set.has(x));
    }

    function bestGraphToken(kind='config') {
        const tokens = getTokens('graph');
        const wanted = kind === 'group'
            ? ['GroupMember.Read.All','Group.Read.All','Directory.Read.All','Directory.ReadWrite.All']
            : ['DeviceManagementConfiguration.Read.All','DeviceManagementConfiguration.ReadWrite.All'];
        return tokens.find(t => tokenHasAny(t, wanted)) || tokens[0] || null;
    }

    function bestAutopatchToken() {
        return getTokens('autopatch')[0] || null;
    }

    function cacheGet(name) {
        return (GM_getValue(KEY.CACHE, {}) || {})[name] || null;
    }

    function cacheSet(name, data, url='') {
        const c = GM_getValue(KEY.CACHE, {}) || {};
        c[name] = { at: Date.now(), url, data };
        GM_setValue(KEY.CACHE, c);
        log('Cached', name, url);
    }

    function classifyResponse(url, data) {
        const u = String(url || '');
        if (/deviceManagement\/deviceConfigurations\?/i.test(u) && Array.isArray(data?.value) && data.value.some(x => x?.qualityUpdatesDeferralPeriodInDays != null)) return CACHE_NAMES.POLICIES;
        if (/WindowsQualityUpdates\/summary/i.test(u) && Array.isArray(data)) return CACHE_NAMES.QUALITY_SUMMARY;
        if (/windowsUpdateCatalogItems\/microsoft\.graph\.windowsQualityUpdateCatalogItem/i.test(u)) return CACHE_NAMES.QUALITY_CATALOG;
        if (/deviceManagement\/windowsFeatureUpdateProfiles/i.test(u) && Array.isArray(data?.value)) return CACHE_NAMES.FEATURE_PROFILES;
        if (/deviceManagement\/windowsDriverUpdateProfiles/i.test(u) && Array.isArray(data?.value)) return CACHE_NAMES.DRIVER_PROFILES;
        if (/WindowsFeatureUpdates\/releasesSummary/i.test(u) && Array.isArray(data)) return CACHE_NAMES.FEATURE_RELEASES;
        if (/WindowsFeatureUpdatesCompletionReleases|windowsFeatureUpdates\/completion/i.test(u)) return CACHE_NAMES.FEATURE_COMPLETION;
        return null;
    }

    function captureJson(url, textOrObject) {
        try {
            const data = typeof textOrObject === 'string' ? JSON.parse(textOrObject) : textOrObject;
            const name = classifyResponse(url, data);
            if (name) cacheSet(name, data, url);
        } catch {}
    }

    function installPortalCapture() {
        const w = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;
        if (w.__apcalV2CaptureInstalled) return;
        w.__apcalV2CaptureInstalled = true;

        try {
            const originalFetch = w.fetch;
            if (originalFetch) {
                w.fetch = function(input, init={}) {
                    let url = '';
                    try {
                        url = typeof input === 'string' ? input : input?.url || '';
                        let auth = authFromHeaders(init?.headers);
                        if (!auth && input?.headers) auth = authFromHeaders(input.headers);
                        if (auth?.startsWith('Bearer ')) saveBearer(auth.slice(7), url);
                    } catch {}
                    const promise = originalFetch.apply(this, arguments);
                    try {
                        promise.then(response => {
                            try {
                                const responseUrl = response?.url || url;
                                if (classifyResponse(responseUrl, null) || /deviceConfigurations|WindowsQualityUpdates|windowsFeatureUpdateProfiles|windowsDriverUpdateProfiles|WindowsFeatureUpdates/i.test(responseUrl)) {
                                    response.clone().text().then(txt => captureJson(responseUrl, txt)).catch(()=>{});
                                }
                            } catch {}
                        }).catch(()=>{});
                    } catch {}
                    return promise;
                };
            }
        } catch (e) { log('fetch capture failed', e); }

        try {
            const XHR = w.XMLHttpRequest;
            if (XHR && !XHR.prototype.__apcalV2Patched) {
                XHR.prototype.__apcalV2Patched = true;
                const oOpen = XHR.prototype.open;
                const oSet = XHR.prototype.setRequestHeader;
                const oSend = XHR.prototype.send;
                XHR.prototype.open = function(method, url) {
                    this.__apcalUrl = String(url || '');
                    return oOpen.apply(this, arguments);
                };
                XHR.prototype.setRequestHeader = function(name, value) {
                    if (String(name).toLowerCase() === 'authorization' && String(value).startsWith('Bearer ')) saveBearer(String(value).slice(7), this.__apcalUrl || '');
                    return oSet.apply(this, arguments);
                };
                XHR.prototype.send = function() {
                    this.addEventListener('load', () => {
                        try {
                            const url = this.responseURL || this.__apcalUrl || '';
                            if (typeof this.responseText === 'string' && this.responseText) captureJson(url, this.responseText);
                        } catch {}
                    }, {once:true});
                    return oSend.apply(this, arguments);
                };
            }
        } catch (e) { log('XHR capture failed', e); }
    }

    function gmRequest({url, method='GET', token=null, body=null, headers={}}) {
        return new Promise((resolve, reject) => {
            const h = {...headers};
            if (token) h.Authorization = `Bearer ${token}`;
            GM_xmlhttpRequest({
                method, url, data: body, headers: h,
                onload: r => {
                    if (r.status >= 200 && r.status < 300) resolve(r);
                    else reject(new Error(`HTTP ${r.status}: ${(r.responseText || '').slice(0,450)}`));
                },
                onerror: e => reject(new Error(`Request failed: ${e?.error || e?.statusText || 'network error'}`))
            });
        });
    }

    async function gmJson(url, token=null, options={}) {
        const r = await gmRequest({url, token, method:options.method || 'GET', body:options.body || null, headers:{Accept:'application/json', ...(options.headers || {})}});
        const j = JSON.parse(r.responseText || 'null');
        captureJson(url, j);
        return j;
    }

    async function tryRefreshPortalData() {
        const errors = [];
        const g = bestGraphToken('config');
        if (g) {
            try {
                await gmJson("https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$filter=isof(%27microsoft.graph.windowsUpdateForBusinessConfiguration%27)", g.token);
            } catch (e) { errors.push(`Graph policies: ${e.message}`); }
            try {
                await gmJson('https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?$expand=assignments', g.token);
            } catch (e) { errors.push(`Graph feature profiles: ${e.message}`); }
            try {
                await gmJson('https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles?$expand=assignments', g.token);
            } catch (e) { errors.push(`Graph driver profiles: ${e.message}`); }
        }
        const a = bestAutopatchToken();
        if (a) {
            try {
                await gmJson('https://services.autopatch.microsoft.com/update-management/v2/WindowsQualityUpdates/summary?planType=WindowsAutopatch', a.token);
            } catch (e) { errors.push(`Autopatch quality summary: ${e.message}`); }
            try {
                await gmJson('https://services.autopatch.microsoft.com/update-management/v2/WindowsFeatureUpdates/releasesSummary?planType=WindowsAutopatch&syncPolicies=true', a.token);
            } catch (e) { errors.push(`Autopatch feature summary: ${e.message}`); }
        }
        return errors;
    }

    function policyMap() {
        const values = cacheGet(CACHE_NAMES.POLICIES)?.data?.value || [];
        return new Map(values.map(p => [String(p.id).toLowerCase(), p]));
    }

    function ringNameFromFull(groupName, full) {
        const prefix = `${groupName} - `;
        if (String(full).startsWith(prefix)) return String(full).slice(prefix.length);
        const m = String(full || '').match(/-\s*(Test|Ring\s*\d+|Last)$/i);
        return m ? m[1].replace(/\s+/g,' ') : full;
    }

    function parsePolicyName(name) {
        const n = String(name || '').trim();
        const m = n.match(/^(.*?)[\s]*[-–—]\s*(Test|Ring\s*\d+|Last)$/i);
        if (!m) return null;
        return { groupName:m[1].trim(), ringName:m[2].replace(/\s+/g,' ').replace(/^ring/i,'Ring').replace(/^test$/i,'Test').replace(/^last$/i,'Last') };
    }

    function countData(id) {
        const overrides = GM_getValue(KEY.COUNT_OVERRIDES, {}) || {};
        if (Number.isFinite(Number(overrides[id]))) return {count:Number(overrides[id]), source:'Override'};
        const counts = GM_getValue(KEY.COUNTS, {}) || {};
        const x = counts[id];
        if (x && Number.isFinite(Number(x.count))) return {count:Number(x.count), source:x.source || 'Graph', at:x.at || 0};
        return {count:null, source:'Unavailable'};
    }

    function buildRings() {
        const pmap = policyMap();
        const summary = cacheGet(CACHE_NAMES.QUALITY_SUMMARY)?.data;
        const rings = [];

        if (Array.isArray(summary) && summary.length) {
            for (const group of summary) {
                for (const dg of (group.deployGroupDetails || [])) {
                    const p = pmap.get(String(dg.wUfBPolicyId || '').toLowerCase()) || {};
                    const cd = countData(dg.deployGroupId);
                    rings.push({
                        source:'Autopatch summary',
                        autopatchGroupId:group.autopatchGroupId || null,
                        autopatchGroup:group.name || '',
                        autopatchGroupStatus:group.autopatchGroupStatus || group.status || '',
                        ringName:ringNameFromFull(group.name || '', dg.name || ''),
                        deploymentGroupId:dg.deployGroupId || null,
                        policyId:dg.wUfBPolicyId || p.id || null,
                        policyName:p.displayName || dg.name || '',
                        qualityPlannedStart:localDate(dg.start),
                        qualityPlannedCompletion:localDate(dg.targetCompletionDate),
                        qualityTarget:dg.target || group.target || '',
                        qualityDeferral:Number(p.qualityUpdatesDeferralPeriodInDays ?? 0),
                        featureDeferral:Number(p.featureUpdatesDeferralPeriodInDays ?? 0),
                        qualityDeadline:Number(p.deadlineForQualityUpdatesInDays ?? 0),
                        featureDeadline:Number(p.deadlineForFeatureUpdatesInDays ?? 0),
                        grace:Number(p.deadlineGracePeriodInDays ?? 0),
                        deviceCount:cd.count,
                        countSource:cd.source
                    });
                }
            }
            return rings;
        }

        // Fallback if only the Intune WUfB policy response has been captured.
        for (const p of pmap.values()) {
            const parsed = parsePolicyName(p.displayName);
            if (!parsed || !/autopatch/i.test(parsed.groupName)) continue;
            rings.push({
                source:'Intune policy fallback',
                autopatchGroupId:null,
                autopatchGroup:parsed.groupName,
                ringName:parsed.ringName,
                deploymentGroupId:null,
                policyId:p.id,
                policyName:p.displayName,
                qualityPlannedStart:null,
                qualityPlannedCompletion:null,
                qualityTarget:'',
                qualityDeferral:Number(p.qualityUpdatesDeferralPeriodInDays ?? 0),
                featureDeferral:Number(p.featureUpdatesDeferralPeriodInDays ?? 0),
                qualityDeadline:Number(p.deadlineForQualityUpdatesInDays ?? 0),
                featureDeadline:Number(p.deadlineForFeatureUpdatesInDays ?? 0),
                grace:Number(p.deadlineGracePeriodInDays ?? 0),
                deviceCount:null,
                countSource:'Unavailable'
            });
        }
        return rings;
    }

    function splitBatches(arr, size=20) {
        const out=[];
        for (let i=0;i<arr.length;i+=size) out.push(arr.slice(i,i+size));
        return out;
    }

    async function refreshDeviceCounts(rings, force=false) {
        const ids = [...new Set(rings.map(r => r.deploymentGroupId).filter(Boolean))];
        if (!ids.length) return {updated:0, skipped:0, error:'No deployment-group IDs available.'};

        const ttl = Math.max(1, Number(settings().countCacheHours || 6)) * 3600_000;
        const counts = GM_getValue(KEY.COUNTS, {}) || {};
        const need = force ? ids : ids.filter(id => !counts[id] || !Number.isFinite(Number(counts[id].count)) || Date.now() - Number(counts[id].at || 0) > ttl);
        if (!need.length) return {updated:0, skipped:ids.length, error:null};

        const tokenObj = bestGraphToken('group');
        if (!tokenObj || !tokenHasAny(tokenObj, ['GroupMember.Read.All','Group.Read.All','Directory.Read.All','Directory.ReadWrite.All'])) {
            return {updated:0, skipped:ids.length-need.length, error:'No captured Graph token with group/member read permission. Counts stay cached/unknown; count overrides remain available.'};
        }

        let updated = 0;
        const errors=[];
        for (const batch of splitBatches(need, 20)) {
            const requests = batch.map((id, i) => ({
                id:String(i+1),
                method:'GET',
                url:`/groups/${id}/transitiveMembers/microsoft.graph.device/$count`,
                headers:{ConsistencyLevel:'eventual'}
            }));
            try {
                const data = await gmJson('https://graph.microsoft.com/v1.0/$batch', tokenObj.token, {
                    method:'POST',
                    body:JSON.stringify({requests}),
                    headers:{'Content-Type':'application/json'}
                });
                for (const res of (data.responses || [])) {
                    const idx = Number(res.id) - 1;
                    const id = batch[idx];
                    if (!id) continue;
                    if (res.status >= 200 && res.status < 300) {
                        const value = typeof res.body === 'number' ? res.body : Number(res.body?.value ?? res.body);
                        if (Number.isFinite(value)) {
                            counts[id] = {count:value, at:Date.now(), source:'Graph transitive device count'};
                            updated++;
                        }
                    } else {
                        errors.push(`${id}: HTTP ${res.status}`);
                    }
                }
            } catch (e) {
                errors.push(e.message);
            }
        }
        GM_setValue(KEY.COUNTS, counts);
        return {updated, skipped:ids.length-need.length, error:errors.length ? errors.slice(0,4).join('; ') : null};
    }

    function getFeatureReleaseCache(version) {
        return (GM_getValue(KEY.FEATURE_RELEASES, {}) || {})[version] || null;
    }

    function setFeatureRelease(version, date, source='Manual') {
        const c = GM_getValue(KEY.FEATURE_RELEASES, {}) || {};
        if (date) c[version] = {date, source, at:Date.now()}; else delete c[version];
        GM_setValue(KEY.FEATURE_RELEASES, c);
    }

    async function fetchFeatureRelease(version) {
        // First try Microsoft's public Windows 11 release-health page. This does not need tenant permissions.
        const url = 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information';
        const r = await gmRequest({url});
        const doc = new DOMParser().parseFromString(r.responseText, 'text/html');
        const wanted = String(version || '').trim().toLowerCase();
        const candidates=[];
        for (const row of doc.querySelectorAll('tr')) {
            const text = row.textContent.replace(/\s+/g,' ').trim();
            if (!text.toLowerCase().includes(wanted)) continue;
            const dates = [...text.matchAll(/\b(20\d{2}-\d{2}-\d{2})\b/g)].map(m => m[1]);
            for (const date of dates) candidates.push({date, text});
        }
        // Prefer a row that explicitly mentions availability/release; otherwise take the earliest date in a version row.
        let candidate = candidates.find(x => /general availability|availability date|release date/i.test(x.text));
        if (!candidate && candidates.length) candidate = candidates.sort((a,b) => a.date.localeCompare(b.date))[0];
        if (!candidate) throw new Error(`Windows ${version} release date was not found on the Microsoft release-information page.`);
        setFeatureRelease(version, candidate.date, 'Microsoft Learn');
        return {date:candidate.date, source:'Microsoft Learn'};
    }

    function featureReleaseSummaryData() {
        const data = cacheGet(CACHE_NAMES.FEATURE_RELEASES)?.data;
        if (Array.isArray(data)) return data;
        if (Array.isArray(data?.value)) return data.value;
        return [];
    }

    function normalizedFeatureVersion(value) {
        const s = String(value || '').trim().toUpperCase();
        const m = s.match(/\b(\d{2}H[12])\b/);
        return m ? m[1] : s.replace(/\s+/g, ' ');
    }

    function featureReleaseTarget(release) {
        return release?.target || release?.featureUpdateVersion || release?.targetVersion || '';
    }

    function featureReleaseMatchesVersion(release, version) {
        const wanted = normalizedFeatureVersion(version);
        const target = normalizedFeatureVersion(featureReleaseTarget(release));
        if (!wanted) return true;
        if (target === wanted) return true;
        return String(featureReleaseTarget(release) || '').toUpperCase().includes(wanted);
    }

    function assignmentGroupId(assignment) {
        return assignment?.target?.groupId || assignment?.target?.groupID || assignment?.groupId || null;
    }

    function phaseGroupId(group) {
        return group?.groupId || group?.id || group?.entraGroupId || group?.deploymentGroupId || null;
    }

    function phaseGroupName(group) {
        return String(group?.groupName || group?.displayName || group?.name || '').trim();
    }

    function firstDateField(obj, names) {
        for (const name of names) {
            const v = obj?.[name];
            const d = localDate(v);
            if (d) return d;
        }
        return null;
    }

    function phaseBaseStart(phase) {
        return firstDateField(phase, ['start','startDate','startDateTime','firstDeploymentDate','firstDeploymentDateTime'])
            || firstDateField(phase?.profile?.rolloutSettings, ['offerStartDateTimeInUTC'])
            || firstDateField(phase?.profile, ['createdDateTime']);
    }

    function phaseOfferInterval(phase) {
        const candidates = [
            phase?.profile?.rolloutSettings?.offerIntervalInDays,
            phase?.offerIntervalInDays,
            phase?.daysBetweenGroups,
            phase?.daysBetweenOffers,
            phase?.deploymentIntervalInDays,
            phase?.intervalInDays
        ];
        for (const value of candidates) {
            const n = Number(value);
            if (Number.isFinite(n) && n >= 0) return n;
        }
        // Current Autopatch feature-release documentation uses seven days between gradual rollout groups.
        return Array.isArray(phase?.groups) && phase.groups.length > 1 ? 7 : 0;
    }

    function featurePhaseMatch(ring, release) {
        if (!release) return null;
        const wantedId = String(ring.deploymentGroupId || '').toLowerCase();
        const wantedNames = new Set([
            String(ring.ringName || '').toLowerCase(),
            `${ring.autopatchGroup || ''} - ${ring.ringName || ''}`.toLowerCase(),
            `Windows Autopatch Update Policy - ${ring.autopatchGroup || ''} - ${ring.ringName || ''}`.toLowerCase()
        ].filter(Boolean));

        for (const phase of (release.phases || [])) {
            const groups = Array.isArray(phase?.groups) ? phase.groups : [];
            let groupIndex = groups.findIndex(g => wantedId && String(phaseGroupId(g) || '').toLowerCase() === wantedId);
            if (groupIndex < 0) {
                groupIndex = groups.findIndex(g => {
                    const n = phaseGroupName(g).toLowerCase();
                    return n && (wantedNames.has(n) || n.endsWith(` - ${String(ring.ringName || '').toLowerCase()}`));
                });
            }
            if (groupIndex >= 0) return {phase, group:groups[groupIndex], groupIndex, match:'phase.groups'};

            const assignments = Array.isArray(phase?.profile?.assignments) ? phase.profile.assignments : [];
            const assignmentIndex = assignments.findIndex(a => wantedId && String(assignmentGroupId(a) || '').toLowerCase() === wantedId);
            if (assignmentIndex >= 0) return {phase, group:null, groupIndex:assignmentIndex, match:'profile.assignments'};
        }
        return null;
    }

    function featureReleaseScopeResolvable(release) {
        return (release?.phases || []).some(phase => {
            if ((phase?.groups || []).some(g => phaseGroupId(g) || phaseGroupName(g))) return true;
            return (phase?.profile?.assignments || []).some(a => assignmentGroupId(a));
        });
    }

    function featureReleaseFirstDate(release) {
        const dates = (release?.phases || []).map(phaseBaseStart).filter(Boolean).sort((a,b)=>a-b);
        return dates[0] || null;
    }

    function featureReleaseLastDate(release) {
        const dates=[];
        for (const phase of (release?.phases || [])) {
            const end = firstDateField(phase?.profile?.rolloutSettings, ['offerEndDateTimeInUTC'])
                || firstDateField(phase, ['end','endDate','targetCompletionDate']);
            if (end) dates.push(end);
            else {
                const start=phaseBaseStart(phase);
                if (start) dates.push(addDays(start, Math.max(0,(phase?.groups?.length || 1)-1) * phaseOfferInterval(phase)));
            }
        }
        dates.sort((a,b)=>b-a);
        return dates[0] || null;
    }

    function releaseRingMatchCount(release, rings) {
        return rings.reduce((n, ring) => n + (featurePhaseMatch(ring, release) ? 1 : 0), 0);
    }

    function resolveFeatureRelease(rings=selectedRings()) {
        const releases = featureReleaseSummaryData();
        const selection = state.featureReleaseId || 'auto';
        if (selection === 'ga') return null;
        if (selection !== 'auto') return releases.find(r => String(r.id) === String(selection)) || null;

        const matching = releases.filter(r => featureReleaseMatchesVersion(r, state.featureVersion));
        if (!matching.length) return null;
        return [...matching].sort((a,b) => {
            const scopeDiff = releaseRingMatchCount(b, rings) - releaseRingMatchCount(a, rings);
            if (scopeDiff) return scopeDiff;
            const ad = featureReleaseFirstDate(a)?.getTime() || 0;
            const bd = featureReleaseFirstDate(b)?.getTime() || 0;
            return bd - ad;
        })[0] || null;
    }

    function driverProfilesData() {
        const data = cacheGet(CACHE_NAMES.DRIVER_PROFILES)?.data;
        return Array.isArray(data?.value) ? data.value : (Array.isArray(data) ? data : []);
    }

    function driverProfileForRing(ring) {
        const profiles = driverProfilesData();
        const groupId = String(ring?.deploymentGroupId || '').toLowerCase();
        if (!profiles.length || !groupId) return null;
        const matches = profiles.filter(profile => (profile?.assignments || []).some(a => String(assignmentGroupId(a) || '').toLowerCase() === groupId));
        if (!matches.length) return null;
        if (matches.length === 1) return matches[0];

        const groupName = String(ring?.autopatchGroup || '').toLowerCase();
        const ringName = String(ring?.ringName || '').toLowerCase();
        return [...matches].sort((a,b) => {
            const score = p => {
                const n = String(p?.displayName || '').toLowerCase();
                return (groupName && n.includes(groupName) ? 2 : 0) + (ringName && n.includes(ringName) ? 1 : 0);
            };
            return score(b) - score(a);
        })[0];
    }

    function driverMonthKey(value) {
        const d = localDate(value);
        if (!d) return '';
        return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
    }

    function getDriverReleaseInfo(value) {
        const d = localDate(value) || new Date();
        const key = driverMonthKey(d);
        const item = state.driverReleaseOverrides?.[key];
        if (item && localDate(item)) return {date:localDate(item), source:'Temporary manual override', key, overridden:true};
        return {date:secondTuesday(d.getFullYear(), d.getMonth()), source:'Patch Tuesday default', key, overridden:false};
    }

    function setDriverReleaseOverride(value, date) {
        const key = driverMonthKey(value);
        if (!key) return;
        state.driverReleaseOverrides ||= {};
        if (date && localDate(date)) state.driverReleaseOverrides[key] = isoDate(date);
        else delete state.driverReleaseOverrides[key];
    }

    function driverDatesForRing(ring, releaseDate) {
        const profile = driverProfileForRing(ring);
        const approvalType = String(profile?.approvalType || '').toLowerCase();
        let deferral = 0;
        let source = 'Driver baseline only; no matching Driver Update profile captured';

        if (profile) {
            if (approvalType === 'automatic') {
                deferral = Math.max(0, Number(profile.deploymentDeferralInDays || 0));
                source = `Driver profile automatic approval (${deferral}d deployment deferral)`;
            } else if (approvalType === 'manual') {
                source = 'Driver profile manual approval; baseline date is treated as the approval/availability date';
            } else {
                source = `Driver profile (${profile.displayName || profile.id || 'unknown approval type'})`;
            }
        }

        const available = addDays(releaseDate, deferral);
        // Microsoft documents that the Quality Update deadline and grace-period settings apply to drivers.
        // The exact deadline starts when the client first detects the approved driver, so this is a planning boundary.
        const deadline = addDays(available, ring.qualityDeadline);
        return {
            available,
            deadline,
            restart:addDays(deadline, ring.grace),
            source,
            phaseName:'',
            approvalType:approvalType || 'unknown',
            driverDeferral:deferral,
            profileName:profile?.displayName || '',
            profileId:profile?.id || null
        };
    }

    function qualityDatesForRing(ring, releaseDate) {
        // The Autopatch service already exposes exact current-release start/completion dates.
        // Use them only when they belong to the same release month; future/previous months are calculated from policy.
        if (ring.qualityPlannedStart && ring.qualityPlannedCompletion && sameMonth(ring.qualityPlannedStart, releaseDate)) {
            return {
                available:localDate(ring.qualityPlannedStart),
                deadline:localDate(ring.qualityPlannedCompletion),
                restart:addDays(ring.qualityPlannedCompletion, ring.grace),
                source:'Autopatch quality plan', phaseName:''
            };
        }
        const available = addDays(releaseDate, ring.qualityDeferral);
        const deadline = addDays(available, ring.qualityDeadline);
        return {available, deadline, restart:addDays(deadline, ring.grace), source:'Update-ring policy calculation', phaseName:''};
    }

    function featureDatesForRing(ring, releaseDate, featureRelease=null) {
        if (featureRelease) {
            const match = featurePhaseMatch(ring, featureRelease);
            if (match) {
                const phase = match.phase;
                const groupStart = firstDateField(match.group, ['start','startDate','startDateTime','offerStartDateTimeInUTC','firstDeploymentDate']);
                const baseStart = phaseBaseStart(phase);
                const interval = phaseOfferInterval(phase);
                const available = groupStart || (baseStart ? addDays(baseStart, Math.max(0, match.groupIndex) * interval) : null);
                if (available) {
                    const deadline = addDays(available, ring.featureDeadline);
                    return {
                        available,
                        deadline,
                        restart:addDays(deadline, ring.grace),
                        source:`Autopatch feature release${interval ? ` (${interval}d offer interval)` : ''}`,
                        phaseName:phase?.name || phase?.displayName || `Phase ${Number(match.groupIndex)+1}`,
                        releaseName:featureRelease?.name || '',
                        targeted:true,
                        match:match.match
                    };
                }
                return {available:null,deadline:null,restart:null,source:'Autopatch release: phase has no usable start date',phaseName:phase?.name||'',releaseName:featureRelease?.name||'',targeted:true,match:match.match};
            }
            if (featureReleaseScopeResolvable(featureRelease)) {
                return {available:null,deadline:null,restart:null,source:'Not targeted by selected Autopatch release',phaseName:'',releaseName:featureRelease?.name||'',targeted:false};
            }
        }

        if (!releaseDate) return {available:null,deadline:null,restart:null,source:'No GA/fallback release date',phaseName:'',targeted:null};
        const available = addDays(releaseDate, ring.featureDeferral);
        const deadline = addDays(available, ring.featureDeadline);
        return {available, deadline, restart:addDays(deadline, ring.grace), source:'GA + update-ring policy fallback', phaseName:'', targeted:null};
    }

    function buildEvents(rings, type, releaseDate, featureRelease=null) {
        const events=[];
        const releaseMarker = type === 'feature' && featureRelease ? featureReleaseFirstDate(featureRelease) : localDate(releaseDate);
        const releaseLabel = type === 'quality'
            ? 'Quality update release'
            : type === 'driver'
                ? 'Driver baseline'
                : featureRelease ? `Feature release: ${featureRelease.name || featureReleaseTarget(featureRelease)}` : 'Feature update GA';
        if (releaseMarker) events.push({kind:'release', date:releaseMarker, label:releaseLabel, count:null, ring:null, group:null});
        for (const ring of rings) {
            const dates = type === 'quality'
                ? qualityDatesForRing(ring, releaseDate)
                : type === 'driver'
                    ? driverDatesForRing(ring, releaseDate)
                    : featureDatesForRing(ring, releaseDate, featureRelease);
            if (!dates || dates.targeted === false) continue;
            const common = {group:ring.autopatchGroup, ring:ring.ringName, count:ring.deviceCount, ringObj:ring, dateSource:dates.source, phaseName:dates.phaseName || '', releaseName:dates.releaseName || ''};
            events.push({...common,kind:'available',label:'Available',date:dates.available});
            events.push({...common,kind:'deadline',label:'Install deadline',date:dates.deadline});
            events.push({...common,kind:'restart',label:'Restart deadline',date:dates.restart});
        }
        return events.filter(e => e.date);
    }

    function groupedByDate(events) {
        const m=new Map();
        for (const e of events) {
            const k=isoDate(e.date);
            if (!m.has(k)) m.set(k,[]);
            m.get(k).push(e);
        }
        return m;
    }

    function statsForKind(events, kind) {
        const es=events.filter(e=>e.kind===kind);
        return {
            rings:es.length,
            known:es.filter(e=>Number.isFinite(Number(e.count))).reduce((s,e)=>s+Number(e.count),0),
            unknown:es.filter(e=>!Number.isFinite(Number(e.count))).length
        };
    }

    function eventDetail(events) {
        return events.filter(e=>e.kind!=='release').map(e => `${e.label}: ${e.group} / ${e.ring}${e.phaseName ? ` / ${e.phaseName}` : ''} — ${Number.isFinite(Number(e.count)) ? `${Number(e.count).toLocaleString()} devices` : 'device count unavailable'} — ${e.dateSource}`).join('\n');
    }

    function calendarHtml(viewDate, events) {
        const y=viewDate.getFullYear(), m=viewDate.getMonth();
        const first=new Date(y,m,1,12), last=new Date(y,m+1,0,12);
        const start=addDays(first,-((first.getDay()+6)%7));
        const end=addDays(last,6-((last.getDay()+6)%7));
        const byDate=groupedByDate(events);
        const offerEvents=events.filter(e=>e.kind==='available' && Number.isFinite(Number(e.count))).sort((a,b)=>a.date-b.date);
        const cumulativeKnown=date=>offerEvents.filter(e=>e.date<=date).reduce((s,e)=>s+Number(e.count),0);
        let html=`<div class="apcal-weekhead">${['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].map(x=>`<div>${x}</div>`).join('')}</div><div class="apcal-grid">`;
        for (let d=new Date(start); d<=end; d=addDays(d,1)) {
            const key=isoDate(d), es=byDate.get(key)||[], outside=d.getMonth()!==m;
            const release=es.find(e=>e.kind==='release');
            const available=statsForKind(es,'available');
            const deadline=statsForKind(es,'deadline');
            const restart=statsForKind(es,'restart');
            html += `<div class="apcal-day ${outside?'outside':''}" data-date="${key}" title="${esc(eventDetail(es))}"><div class="apcal-daynum">${d.getDate()}</div>`;
            if (release) html += `<div class="apcal-chip release">${esc(release.label)}</div>`;
            const chip=(label,st,cls,extra='')=>{
                if (!st.rings) return '';
                const countText = st.known ? `<b>${st.known.toLocaleString()}</b> dev.` : '';
                const unknownText = st.unknown ? `${st.known?' + ':''}${st.unknown} ring${st.unknown===1?'':'s'} ?` : '';
                return `<div class="apcal-chip ${cls}">${label} ${countText}${unknownText}${extra}</div>`;
            };
            html += chip('Available',available,'offer',available.known?` <span class="apcal-sigma">Σ ${cumulativeKnown(d).toLocaleString()}</span>`:'');
            html += chip('Deadline',deadline,'deadline');
            html += chip('Restart',restart,'restart');
            html += `</div>`;
        }
        return html+'</div>';
    }

    function ringTableHtml(rings, type, releaseDate, featureRelease=null) {
        const rows = [...rings].sort((a,b) => {
            const ga=a.autopatchGroup.localeCompare(b.autopatchGroup); if (ga) return ga;
            const rank=x=>/^Test$/i.test(x)?0:/^Ring\s*(\d+)/i.test(x)?Number(x.match(/\d+/)?.[0]||0)+1:/^Last$/i.test(x)?999:500;
            return rank(a.ringName)-rank(b.ringName);
        }).map(r => {
            const d=type==='quality' ? qualityDatesForRing(r,releaseDate) : type==='driver' ? driverDatesForRing(r,releaseDate) : featureDatesForRing(r,releaseDate,featureRelease);
            const def=type==='quality' ? r.qualityDeferral : type==='driver' ? Number(d.driverDeferral || 0) : r.featureDeferral;
            const dl=type==='feature' ? r.featureDeadline : r.qualityDeadline;
            const phase = type==='feature'
                ? (d.phaseName || (d.targeted===false ? 'Not targeted' : 'Fallback'))
                : type==='driver'
                    ? `${d.approvalType || 'unknown'}${d.profileName ? ` — ${d.profileName}` : ''}`
                    : '';
            return `<tr><td>${esc(r.autopatchGroup)}</td><td>${esc(r.ringName)}</td><td>${r.deviceCount==null?'<span class="apcal-muted">unknown</span>':Number(r.deviceCount).toLocaleString()}</td><td>${esc(phase)}</td><td>${isoDate(d.available)}</td><td>${isoDate(d.deadline)}</td><td>${isoDate(d.restart)}</td><td>${def}</td><td>${dl}</td><td>${r.grace}</td><td>${esc(d.source)}</td></tr>`;
        }).join('');
        return `<details class="apcal-details"><summary>Ring details (${rings.length})</summary><div class="apcal-tablewrap"><table class="apcal-table"><thead><tr><th>Autopatch group</th><th>Ring</th><th>Devices</th><th>Phase / approval</th><th>Available</th><th>Install deadline</th><th>Restart deadline</th><th>Deferral</th><th>Deadline</th><th>Grace</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
    }

    function ensureCss() {
        if (document.getElementById('apcal-v2-css')) return;
        const s=document.createElement('style'); s.id='apcal-v2-css';
        s.textContent=`
#apcal-v2-overlay{position:fixed;inset:0;z-index:350000;background:rgba(0,0,0,.38);display:flex;align-items:center;justify-content:center;padding:20px;box-sizing:border-box;font-family:"Segoe UI",sans-serif}
#apcal-v2-dialog{width:min(1580px,calc(100vw - 40px));height:min(920px,calc(100vh - 40px));display:flex;flex-direction:column;overflow:hidden;background:var(--colorContainerBackgroundPrimary,#fff);color:var(--colorTextPrimary,#323130);border:1px solid var(--colorContainerBorderSecondary,#d2d0ce);box-shadow:var(--shadowLevel4,0 25px 58px rgba(0,0,0,.32))}
.apcal-titlebar{display:flex;align-items:center;gap:12px;min-height:58px;padding:0 18px;border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9)}
.apcal-title{font-size:20px;font-weight:600}.apcal-subtitle{font-size:12px;color:var(--colorTextSecondary,#605e5c)}.apcal-spacer{flex:1}
.apcal-btn{height:32px;padding:0 10px;border:1px solid var(--colorControlBorder,#8a8886);background:var(--colorControlBackground,#fff);color:var(--colorTextPrimary,#323130);cursor:pointer;font:13px "Segoe UI",sans-serif}.apcal-btn:hover{background:var(--colorControlBackgroundHover,#f3f2f1)}
.apcal-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 18px;border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9)}
.apcal-toolbar select,.apcal-toolbar input{height:32px;padding:0 8px;box-sizing:border-box;border:1px solid var(--colorControlBorder,#8a8886);background:var(--colorControlBackground,#fff);color:var(--colorTextPrimary,#323130)}
.apcal-status{min-height:28px;display:flex;align-items:center;padding:0 18px;font-size:12px;color:var(--colorTextSecondary,#605e5c);border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9)}.apcal-error{color:var(--colorTextError,#d13438)}
.apcal-body{flex:1;min-height:0;overflow:auto;padding:14px 18px}.apcal-summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.apcal-stat{min-width:130px;border:1px solid var(--colorContainerBorderPrimary,#edebe9);padding:8px 10px;background:var(--colorContainerBackgroundSecondary,#f8f8f8)}
.apcal-weekhead,.apcal-grid{display:grid;grid-template-columns:repeat(7,minmax(130px,1fr))}.apcal-weekhead>div{padding:6px 7px;font-weight:600;border-bottom:1px solid var(--colorContainerBorderSecondary,#d2d0ce)}
.apcal-day{min-height:122px;padding:6px;box-sizing:border-box;border-right:1px solid var(--colorContainerBorderPrimary,#edebe9);border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9)}.apcal-day:nth-child(7n+1){border-left:1px solid var(--colorContainerBorderPrimary,#edebe9)}.apcal-day.outside{opacity:.45}.apcal-daynum{font-weight:600;margin-bottom:4px}
.apcal-chip{font-size:11px;line-height:15px;padding:3px 5px;margin:3px 0;border-radius:2px;background:var(--colorContainerBackgroundSecondary,#f3f2f1)}.apcal-chip.release{border-left:3px solid #8764b8}.apcal-chip.offer{border-left:3px solid #0078d4}.apcal-chip.deadline{border-left:3px solid #ffb900}.apcal-chip.restart{border-left:3px solid #d13438}.apcal-sigma{opacity:.75;margin-left:4px}
.apcal-note{margin:10px 0;font-size:12px;color:var(--colorTextSecondary,#605e5c)}.apcal-muted{color:var(--colorTextSecondary,#605e5c)}
.apcal-details{margin-top:14px}.apcal-details>summary{cursor:pointer;font-weight:600}.apcal-tablewrap{overflow:auto;margin-top:8px}.apcal-table{width:100%;border-collapse:collapse;font-size:12px}.apcal-table th,.apcal-table td{padding:7px 8px;border-bottom:1px solid var(--colorContainerBorderPrimary,#edebe9);text-align:left;white-space:nowrap}.apcal-table th{position:sticky;top:0;background:var(--colorContainerBackgroundPrimary,#fff)}
.apcal-group-actions{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:2px!important;padding-left:4px!important;padding-right:4px!important;box-sizing:border-box!important;white-space:nowrap}
.apcal-native-group-btn{display:inline-flex;align-items:center;gap:5px;height:28px;min-width:72px;padding:0 7px;border:0;background:transparent;color:var(--colorButtonToolbardForeground,var(--colorTextPrimary,#323130));cursor:pointer;font:13px "Segoe UI",sans-serif;white-space:nowrap}
.apcal-native-group-btn:hover{background:var(--colorControlBackgroundHover,#f3f2f1)}
.apcal-native-group-btn .apcal-group-calendar-icon{font-family:FabricMDL2Icons;font-style:normal;font-size:14px;line-height:1}
.apcal-group-context-cell{overflow:visible!important}
#apcal-v2-command{cursor:pointer!important}
.apcal-config-grid{display:grid;grid-template-columns:minmax(240px,1fr) 140px;gap:8px;max-width:760px}.apcal-config-grid input{height:30px;background:var(--colorControlBackground,#fff);color:var(--colorTextPrimary,#323130);border:1px solid var(--colorControlBorder,#8a8886);padding:0 7px}
@media(max-width:900px){#apcal-v2-overlay{padding:6px}#apcal-v2-dialog{width:calc(100vw - 12px);height:calc(100vh - 12px)}.apcal-weekhead,.apcal-grid{grid-template-columns:repeat(7,minmax(105px,1fr))}}
`;
        document.documentElement.appendChild(s);
    }

    const state={
        groupId:'*', groupName:'All groups', type:'quality', viewDate:new Date(), featureVersion:settings().featureVersion,
        featureRelease:null, featureReleaseId:settings().featureReleaseSelection || 'auto', rings:[], driverReleaseOverrides:{}
    };

    function selectedRings() {
        if (state.groupId === '*') return state.rings;
        return state.rings.filter(r => r.autopatchGroupId === state.groupId || (!r.autopatchGroupId && r.autopatchGroup === state.groupName));
    }

    function setStatus(text, error=false) {
        const el=document.getElementById('apcal-v2-status');
        if (!el) return;
        el.textContent=text;
        el.className='apcal-status'+(error?' apcal-error':'');
    }

    function updateGroupSelect() {
        const sel=document.getElementById('apcal-v2-group'); if (!sel) return;
        const groups=[];
        const seen=new Set();
        for (const r of state.rings) {
            const id=r.autopatchGroupId || `name:${r.autopatchGroup}`;
            if (seen.has(id)) continue;
            seen.add(id); groups.push({id,name:r.autopatchGroup});
        }
        groups.sort((a,b)=>a.name.localeCompare(b.name));
        sel.innerHTML=`<option value="*">All groups</option>`+groups.map(g=>`<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('');
        const target=state.groupId==='*'?'*':state.groupId || `name:${state.groupName}`;
        if ([...sel.options].some(o=>o.value===target)) sel.value=target; else {sel.value='*';state.groupId='*';state.groupName='All groups';}
    }

    function featureReleaseOptionLabel(release) {
        const target = featureReleaseTarget(release);
        const start = featureReleaseFirstDate(release);
        return `${release?.name || 'Unnamed release'}${target ? ` — ${target}` : ''}${start ? ` — ${isoDate(start)}` : ''}`;
    }

    function updateFeatureReleaseSelect() {
        const sel=document.getElementById('apcal-v2-feature-release');
        if (!sel) return;
        const releases=featureReleaseSummaryData().filter(r=>featureReleaseMatchesVersion(r,state.featureVersion));
        sel.innerHTML=`<option value="auto">Auto-select matching Autopatch release</option><option value="ga">GA + update-ring policy fallback</option>`+
            releases.sort((a,b)=>(featureReleaseFirstDate(b)?.getTime()||0)-(featureReleaseFirstDate(a)?.getTime()||0)).map(r=>`<option value="${esc(r.id)}">${esc(featureReleaseOptionLabel(r))}</option>`).join('');
        if ([...sel.options].some(o=>o.value===state.featureReleaseId)) sel.value=state.featureReleaseId;
        else {state.featureReleaseId='auto';sel.value='auto';}
    }

    function updateDriverControls() {
        const controls=document.getElementById('apcal-v2-driver-controls');
        const input=document.getElementById('apcal-v2-driver-date');
        const source=document.getElementById('apcal-v2-driver-source');
        if (!controls || !input) return;
        const info=getDriverReleaseInfo(state.viewDate);
        input.value=isoDate(info.date);
        if (source) source.textContent=info.overridden ? `Temporary override for ${info.key} (not saved)` : `Patch Tuesday default for ${info.key}`;
    }

    async function refreshData(forceCounts=false) {
        setStatus('Refreshing captured Intune/Autopatch data…');
        const errors=await tryRefreshPortalData();
        state.rings=buildRings();
        updateGroupSelect();
        updateFeatureReleaseSelect();
        if (state.rings.length) {
            const cr=await refreshDeviceCounts(state.rings, forceCounts);
            state.rings=buildRings();
            updateGroupSelect();
            updateFeatureReleaseSelect();
            let msg=`Loaded ${state.rings.length} deployment rings across ${new Set(state.rings.map(r=>r.autopatchGroup)).size} Autopatch groups.`;
            const frCount=featureReleaseSummaryData().length; if(frCount) msg += ` ${frCount} Autopatch feature release(s) captured.`;
            const dpCount=driverProfilesData().length; if(dpCount) msg += ` ${dpCount} Driver Update profile(s) captured.`;
            if (cr.updated) msg += ` Updated ${cr.updated} device counts.`;
            if (cr.error) msg += ` ${cr.error}`;
            if (errors.length) msg += ` Some direct refresh calls were unavailable; cached portal data is being used.`;
            setStatus(msg, false);
        } else {
            setStatus('No Autopatch ring data captured yet. Open/refresh the Intune “Update rings” tab once; this script then reuses the same portal responses.', true);
        }
        render();
        injectNativeButtons();
    }

    async function ensureFeatureRelease() {
        const cached=getFeatureReleaseCache(state.featureVersion);
        if (cached?.date) {state.featureRelease=cached.date; return cached;}
        try {
            const x=await fetchFeatureRelease(state.featureVersion);
            state.featureRelease=x.date; return x;
        } catch (e) {
            state.featureRelease=null; throw e;
        }
    }

    function render() {
        const body=document.getElementById('apcal-v2-body'); if (!body) return;
        const month=document.getElementById('apcal-v2-month'); if (month) month.textContent=monthLabel(state.viewDate);
        if (state.type==='driver') updateDriverControls();

        const rings=selectedRings();
        const featureRelease=state.type==='feature' ? resolveFeatureRelease(rings) : null;
        const driverRelease=state.type==='driver' ? getDriverReleaseInfo(state.viewDate) : null;
        let releaseDate=null;
        if (state.type==='quality') releaseDate=secondTuesday(state.viewDate.getFullYear(),state.viewDate.getMonth());
        else if (state.type==='driver') releaseDate=driverRelease?.date || null;
        else if (featureRelease) releaseDate=featureReleaseFirstDate(featureRelease) || (state.featureRelease ? localDate(state.featureRelease) : null);
        else if (state.featureRelease) releaseDate=localDate(state.featureRelease);

        if (!releaseDate && !featureRelease) {
            body.innerHTML='<div class="apcal-error">No update schedule is available. For Feature Updates refresh Autopatch data, fetch the Microsoft GA date, or enter the date manually.</div>';
            return;
        }

        const events=buildEvents(rings,state.type,releaseDate,featureRelease);
        const scheduledRingSet=new Set(events.filter(e=>e.kind==='available'&&e.ringObj).map(e=>e.ringObj));
        const scopeRings=state.type==='feature' && featureRelease && featureReleaseScopeResolvable(featureRelease) ? [...scheduledRingSet] : rings;
        const known=scopeRings.filter(r=>Number.isFinite(Number(r.deviceCount))).reduce((sum,r)=>sum+Number(r.deviceCount),0);
        const unknown=scopeRings.filter(r=>!Number.isFinite(Number(r.deviceCount))).length;
        const qualitySummaryAge=cacheGet(CACHE_NAMES.QUALITY_SUMMARY)?.at;
        const featureSummaryAge=cacheGet(CACHE_NAMES.FEATURE_RELEASES)?.at;
        const driverProfileCount=driverProfilesData().length;
        const planLabel=state.type==='quality'
            ? (qualitySummaryAge?`Autopatch plan captured ${new Date(qualitySummaryAge).toLocaleTimeString()}`:'Update-ring policy fallback')
            : state.type==='driver'
                ? `${driverRelease?.source || 'Driver baseline'}${driverProfileCount ? ` · ${driverProfileCount} Driver Update profile(s) captured` : ' · Driver Update profiles unavailable'}`
                : (featureRelease?`${featureRelease.name || 'Autopatch release'}${featureSummaryAge?` · captured ${new Date(featureSummaryAge).toLocaleTimeString()}`:''}`:'GA + update-ring policy fallback');
        const releaseLabel=state.type==='feature' && featureRelease ? `${featureRelease.name || 'Autopatch release'} / ${featureReleaseTarget(featureRelease) || state.featureVersion}` : isoDate(releaseDate);
        const finalOffer=state.type==='feature'&&featureRelease?featureReleaseLastDate(featureRelease):null;
        const releaseHeading=state.type==='driver' ? 'Driver baseline' : (state.type==='feature'&&featureRelease ? 'Feature release' : 'Release');
        const note=state.type==='quality'
            ? "For the current Quality Update rollout, “Available” and “Install deadline” use Autopatch's own start and targetCompletionDate when available. Other months use Patch Tuesday + configured deferral/deadline. “Restart” adds the configured grace period."
            : state.type==='driver'
                ? "Driver Updates use Patch Tuesday as the planning baseline for each month. You can temporarily override that date for the currently open calendar; the override is not saved and Patch Tuesday is restored when the calendar is reopened. If the matching Intune Driver Update profile is available, automatic profiles add deploymentDeferralInDays; manual profiles treat the selected baseline as the approval/availability date. Quality Update deadline and grace settings are then used as the planning boundary for driver install/restart. The real deadline begins when a client first detects the approved driver, so these driver dates are estimates rather than an exact per-device schedule."
                : featureRelease
                    ? "Feature Update “Available” dates use the selected Autopatch multi-phase release. The script maps each phase to the actual deployment-ring Entra group and applies the phase profile's offer start plus offer interval. Install and restart boundaries then use that ring's configured feature-update deadline and grace period. Rings not targeted by the selected release are not added to the calendar."
                    : "No matching Autopatch multi-phase release is selected/available. Dates therefore use the Microsoft GA date + the update ring's feature deferral, deadline and grace period.";

        body.innerHTML=`
            <div class="apcal-summary">
                <div class="apcal-stat"><b>${esc(releaseHeading)}</b><br>${esc(releaseLabel)}</div>
                <div class="apcal-stat"><b>Scope</b><br>${esc(state.groupId==='*'?'All groups':state.groupName)}</div>
                <div class="apcal-stat"><b>Scheduled rings</b><br>${scopeRings.length}${rings.length!==scopeRings.length?` <span class="apcal-muted">of ${rings.length}</span>`:''}</div>
                <div class="apcal-stat"><b>Known devices</b><br>${known.toLocaleString()}${unknown?` <span class="apcal-muted">+ ${unknown} ring(s) unknown</span>`:''}</div>
                <div class="apcal-stat"><b>Plan source</b><br>${esc(planLabel)}${finalOffer?`<br><span class="apcal-muted">final offer ${isoDate(finalOffer)}</span>`:''}</div>
            </div>
            ${calendarHtml(state.viewDate,events)}
            <div class="apcal-note">${note}</div>
            ${ringTableHtml(rings,state.type,releaseDate,featureRelease)}
        `;
    }

    function saveFeatureVersion(v) {
        const s=settings(); s.featureVersion=v; GM_setValue(KEY.SETTINGS,s);
    }

    function openOverrides() {
        const body=document.getElementById('apcal-v2-body'); if(!body)return;
        const overrides=GM_getValue(KEY.COUNT_OVERRIDES,{})||{};
        const rings=state.rings.filter(r=>r.deploymentGroupId);
        body.innerHTML=`<h3>Device-count overrides</h3><p class="apcal-note">Normally the script batches Graph member-count requests for the actual Autopatch deployment groups. Use overrides only if the current portal token cannot read group membership. Blank values remove an override.</p><div class="apcal-config-grid">${rings.map(r=>`<label>${esc(r.autopatchGroup)} / ${esc(r.ringName)}<br><span class="apcal-muted">${esc(r.deploymentGroupId)}</span></label><input type="number" min="0" data-group-id="${esc(r.deploymentGroupId)}" value="${overrides[r.deploymentGroupId]??''}" placeholder="${r.deviceCount??'unknown'}">`).join('')}</div><p><button class="apcal-btn" id="apcal-save-overrides">Save overrides</button> <button class="apcal-btn" id="apcal-clear-count-cache">Clear Graph count cache</button> <button class="apcal-btn" id="apcal-back">Back to calendar</button></p>`;
        body.querySelector('#apcal-save-overrides').onclick=()=>{
            const x={...overrides};
            for(const input of body.querySelectorAll('input[data-group-id]')){
                const id=input.dataset.groupId, val=input.value.trim();
                if(val==='') delete x[id]; else if(Number.isFinite(Number(val))&&Number(val)>=0)x[id]=Number(val);
            }
            GM_setValue(KEY.COUNT_OVERRIDES,x); state.rings=buildRings(); render();
        };
        body.querySelector('#apcal-clear-count-cache').onclick=()=>{GM_setValue(KEY.COUNTS,{});state.rings=buildRings();render();};
        body.querySelector('#apcal-back').onclick=()=>render();
    }

    async function openCalendar(groupId='*', groupName='All groups') {
        ensureCss();
        document.getElementById('apcal-v2-overlay')?.remove();
        state.groupId=groupId || '*'; state.groupName=groupName || 'All groups'; state.type='quality'; state.viewDate=new Date();
        state.featureVersion=settings().featureVersion || '25H2';
        state.featureReleaseId=settings().featureReleaseSelection || 'auto';
        state.driverReleaseOverrides={};
        const cached=getFeatureReleaseCache(state.featureVersion); state.featureRelease=cached?.date || null;

        const overlay=document.createElement('div'); overlay.id='apcal-v2-overlay';
        overlay.innerHTML=`<div id="apcal-v2-dialog"><div class="apcal-titlebar"><div><div class="apcal-title">Autopatch calendar</div><div class="apcal-subtitle">${esc(groupId==='*'?'All Autopatch groups':groupName)}</div></div><span class="apcal-spacer"></span><button class="apcal-btn" id="apcal-v2-refresh">Refresh data</button><button class="apcal-btn" id="apcal-v2-counts">Refresh counts</button><button class="apcal-btn" id="apcal-v2-overrides">Count overrides</button><button class="apcal-btn" id="apcal-v2-close">Close</button></div><div class="apcal-toolbar"><label>Group <select id="apcal-v2-group"></select></label><label>Update <select id="apcal-v2-type"><option value="quality">Quality update</option><option value="feature">Feature update</option><option value="driver">Driver update</option></select></label><span id="apcal-v2-feature-controls" style="display:none;align-items:center;gap:8px"><label>Version <input id="apcal-v2-feature-version" value="${esc(state.featureVersion)}" size="7"></label><label>Autopatch release <select id="apcal-v2-feature-release"></select></label><label>GA fallback <input id="apcal-v2-feature-date" type="date" value="${esc(state.featureRelease||'')}"></label><button class="apcal-btn" id="apcal-v2-feature-fetch">Fetch Microsoft GA</button></span><span id="apcal-v2-driver-controls" style="display:none;align-items:center;gap:8px"><label>Driver baseline <input id="apcal-v2-driver-date" type="date"></label><button class="apcal-btn" id="apcal-v2-driver-patch-tuesday">Use Patch Tuesday</button><span class="apcal-muted" id="apcal-v2-driver-source"></span></span><button class="apcal-btn" id="apcal-v2-prev">◀</button><b id="apcal-v2-month"></b><button class="apcal-btn" id="apcal-v2-next">▶</button></div><div class="apcal-status" id="apcal-v2-status">Loading…</div><div class="apcal-body" id="apcal-v2-body"></div></div>`;
        document.documentElement.appendChild(overlay);

        overlay.querySelector('#apcal-v2-close').onclick=()=>overlay.remove();
        overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.remove();});
        overlay.querySelector('#apcal-v2-prev').onclick=()=>{state.viewDate=new Date(state.viewDate.getFullYear(),state.viewDate.getMonth()-1,1,12);render();};
        overlay.querySelector('#apcal-v2-next').onclick=()=>{state.viewDate=new Date(state.viewDate.getFullYear(),state.viewDate.getMonth()+1,1,12);render();};
        overlay.querySelector('#apcal-v2-refresh').onclick=()=>refreshData(false);
        overlay.querySelector('#apcal-v2-counts').onclick=()=>refreshData(true);
        overlay.querySelector('#apcal-v2-overrides').onclick=()=>openOverrides();
        overlay.querySelector('#apcal-v2-group').onchange=e=>{
            const v=e.target.value; state.groupId=v;
            state.groupName=v==='*'?'All groups':e.target.options[e.target.selectedIndex].textContent; render();
        };
        overlay.querySelector('#apcal-v2-type').onchange=async e=>{
            state.type=e.target.value;
            const fc=overlay.querySelector('#apcal-v2-feature-controls'); fc.style.display=state.type==='feature'?'inline-flex':'none';
            const dc=overlay.querySelector('#apcal-v2-driver-controls'); dc.style.display=state.type==='driver'?'inline-flex':'none';
            if(state.type==='driver'){
                updateDriverControls();
                const info=getDriverReleaseInfo(state.viewDate);
                setStatus(`Driver baseline for ${info.key}: ${isoDate(info.date)} (${info.source}). Driver-profile deferrals are applied when available.`);
            }
            if(state.type==='feature'){
                updateFeatureReleaseSelect();
                const rel=resolveFeatureRelease(selectedRings());
                if(rel){
                    const d=featureReleaseFirstDate(rel); if(d) state.viewDate=new Date(d.getFullYear(),d.getMonth(),1,12);
                    setStatus(`Using Autopatch feature release: ${rel.name || rel.id} (${featureReleaseTarget(rel) || state.featureVersion}).`);
                } else if(!state.featureRelease){
                    setStatus(`No matching Autopatch release captured. Looking up Windows ${state.featureVersion} GA date from Microsoft…`);
                    try{const x=await ensureFeatureRelease();overlay.querySelector('#apcal-v2-feature-date').value=x.date;state.viewDate=new Date(localDate(x.date).getFullYear(),localDate(x.date).getMonth(),1,12);setStatus(`GA fallback ${state.featureVersion}: ${x.date} (${x.source})`);}catch(err){setStatus(err.message,true);}
                }
            }
            render();
        };
        overlay.querySelector('#apcal-v2-feature-version').onchange=e=>{state.featureVersion=e.target.value.trim();state.featureReleaseId='auto';saveFeatureVersion(state.featureVersion);const c=getFeatureReleaseCache(state.featureVersion);state.featureRelease=c?.date||null;overlay.querySelector('#apcal-v2-feature-date').value=state.featureRelease||'';updateFeatureReleaseSelect();const rel=resolveFeatureRelease(selectedRings());const d=rel?featureReleaseFirstDate(rel):null;if(d)state.viewDate=new Date(d.getFullYear(),d.getMonth(),1,12);render();};
        overlay.querySelector('#apcal-v2-feature-release').onchange=e=>{state.featureReleaseId=e.target.value;const st=settings();st.featureReleaseSelection=state.featureReleaseId;GM_setValue(KEY.SETTINGS,st);const rel=resolveFeatureRelease(selectedRings());const d=rel?featureReleaseFirstDate(rel):(state.featureRelease?localDate(state.featureRelease):null);if(d)state.viewDate=new Date(d.getFullYear(),d.getMonth(),1,12);render();};
        overlay.querySelector('#apcal-v2-feature-date').onchange=e=>{state.featureRelease=e.target.value||null;if(state.featureRelease)setFeatureRelease(state.featureVersion,state.featureRelease,'Manual');render();};
        overlay.querySelector('#apcal-v2-feature-fetch').onclick=async()=>{const v=overlay.querySelector('#apcal-v2-feature-version').value.trim();state.featureVersion=v;saveFeatureVersion(v);setStatus(`Reading Windows ${v} GA date from Microsoft…`);try{const x=await fetchFeatureRelease(v);state.featureRelease=x.date;overlay.querySelector('#apcal-v2-feature-date').value=x.date;if(state.featureReleaseId==='ga'){const d=localDate(x.date);state.viewDate=new Date(d.getFullYear(),d.getMonth(),1,12);}setStatus(`GA fallback ${v}: ${x.date} (${x.source})`);render();}catch(e){setStatus(e.message,true);}};
        overlay.querySelector('#apcal-v2-driver-date').onchange=e=>{
            const value=e.target.value||null;
            setDriverReleaseOverride(state.viewDate,value);
            const info=getDriverReleaseInfo(state.viewDate);
            setStatus(`Driver baseline for ${info.key}: ${isoDate(info.date)} (${info.source}). This override is not saved.`);
            render();
        };
        overlay.querySelector('#apcal-v2-driver-patch-tuesday').onclick=()=>{
            setDriverReleaseOverride(state.viewDate,null);
            const info=getDriverReleaseInfo(state.viewDate);
            setStatus(`Driver baseline reset to Patch Tuesday: ${isoDate(info.date)}.`);
            render();
        };

        state.rings=buildRings();
        updateGroupSelect();
        updateFeatureReleaseSelect();
        updateDriverControls();
        render();
        await refreshData(false);
    }

    function parseAutopatchGroupLink(a) {
        const href=String(a?.href||'');
        let id=null;
        try {
            const m=href.match(/\/autopatchGroup\/([^/?#]+)/i);
            if(m){const decoded=decodeURIComponent(m[1]);const o=JSON.parse(decoded);id=o.id||null;}
        } catch {}
        return {id,name:a?.textContent?.trim()||''};
    }

    function createNativeCommandButton() {
        const b=document.createElement('button');
        b.type='button'; b.role='menuitem'; b.id='apcal-v2-command';
        b.className='ms-Button ms-Button--commandBar ms-CommandBarItem-link';
        b.innerHTML='<span class="ms-Button-flexContainer" data-automationid="splitbuttonprimary"><span style="font-family:FabricMDL2Icons;margin-right:7px"></span><span class="ms-Button-textContainer"><span class="ms-Button-label">Autopatch calendar</span></span></span>';
        b.onclick=e=>{e.preventDefault();e.stopPropagation();openCalendar('*','All groups');};
        return b;
    }

    function injectNativeButtons() {
        if (!document.body) return;
        const updateTab=document.querySelector('[role="tab"][name="Update rings"][aria-selected="true"], [role="tab"][data-content="Update rings"][aria-selected="true"]');
        if (!updateTab) return;

        if (!document.getElementById('apcal-v2-command')) {
            const exportBtn=[...document.querySelectorAll('button')].find(b=>b.classList.contains('automation-id-export') || b.getAttribute('aria-label')==='Export');
            const commandSet=exportBtn?.closest('.ms-CommandBar-primaryCommand') || document.querySelector('.ms-CommandBar-primaryCommand');
            if (commandSet) {
                const item=document.createElement('div'); item.className='ms-OverflowSet-item'; item.role='none'; item.dataset.apcalCommandItem='1'; item.appendChild(createNativeCommandButton());
                const exportItem=exportBtn?.closest('.ms-OverflowSet-item');
                if(exportItem?.parentElement===commandSet) exportItem.after(item); else commandSet.appendChild(item);
            }
        }

        const groupLinks=[...document.querySelectorAll('a[href*="AutopatchGroupOverview.ReactView"][href*="autopatchGroup"]')];
        for(const a of groupLinks){
            const header=a.closest('.ms-GroupHeader,[class*="ms-GroupHeader"]');
            if(!header) continue;

            const info=parseAutopatchGroupLink(a);
            const menuBtn=header.querySelector('button[name="contextMenu"]');
            if(!menuBtn) continue;

            // In the Intune grouped list, this is the right-most contextual-menu cell.
            // Put Calendar directly before the native three-dots button so it is visible
            // without opening the Autopatch group or any edit/detail blade.
            const menuHost=menuBtn.parentElement;
            const contextCell=menuBtn.closest('[data-automation-key="contextualMenu"]');
            if(!menuHost) continue;

            contextCell?.classList.add('apcal-group-context-cell');
            menuHost.classList.add('apcal-group-actions');

            let b=menuHost.querySelector(':scope > .apcal-native-group-btn');
            if(!b){
                // Remove an obsolete button from an earlier injection location if the
                // React list re-used the same group header while this script was updated.
                header.querySelectorAll('.apcal-native-group-btn').forEach(x=>x.remove());

                b=document.createElement('button');
                b.type='button';
                b.className='apcal-native-group-btn';
                b.title=`Open Autopatch calendar for ${info.name}`;
                b.setAttribute('aria-label',`Open Autopatch calendar for ${info.name}`);
                b.innerHTML='<span class="apcal-group-calendar-icon" aria-hidden="true">\uE787</span><span>Calendar</span>';
                const open=e=>{
                    e.preventDefault();
                    e.stopPropagation();
                    openCalendar(info.id || menuBtn.id || `name:${info.name}`, info.name);
                };
                b.addEventListener('mousedown',e=>e.stopPropagation());
                b.addEventListener('click',open);
                menuHost.insertBefore(b,menuBtn);
            }
        }

    }

    installPortalCapture();

    function init() {
        ensureCss();
        // v0.7: no floating/global fallback button. UI is injected only on the
        // selected Update rings tab (command bar + Autopatch group rows).
        document.getElementById('apcal-v2-fallback')?.remove();
        injectNativeButtons();
        const mo=new MutationObserver(()=>{
            document.getElementById('apcal-v2-fallback')?.remove();
            injectNativeButtons();
        });
        mo.observe(document.documentElement,{subtree:true,childList:true});
        setInterval(()=>{
            document.getElementById('apcal-v2-fallback')?.remove();
            injectNativeButtons();
        },2500);
    }

    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true}); else init();
})();
