// ==UserScript==
// @name         Intune & Entra Naming Designer
// @namespace    xento.betterintuneui
// @version      5.0.0
// @description  Flexible naming templates for Entra groups and Intune policies, profiles, apps, scripts and updates.
// @author       Xento
// @match        https://intune.microsoft.com/*
// @match        https://entra.microsoft.com/*
// @match        https://portal.azure.com/*
// @match        https://reactblade.portal.azure.net/*
// @match        https://*.reactblade.portal.azure.net/*
// @match        https://reactblade-ms.portal.azure.net/*
// @match        https://*.reactblade-ms.portal.azure.net/*
// @match        https://reactblade-rc.portal.azure.net/*
// @match        https://*.reactblade-rc.portal.azure.net/*
// @grant        GM_getValue
// @grant        GM_setValue
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    const VERSION = '5.0.0';
    const PREFIX = 'tm-intune-entra-naming-v5';

    // Stable keys: keeps v3 configuration.
    const STORAGE_KEY = 'tm-entra-group-naming:templates';
    const LAST_TEMPLATE_KEY = 'tm-entra-group-naming:lastTemplate';
    const BUILTIN_VERSION_KEY = 'tm-entra-group-naming:builtinVersion';
    const BUILTIN_VERSION = 5;

    // v2 migration fallback.
    const LEGACY_STORAGE_KEY = 'tm-entra-group-naming-v2:templates';
    const LEGACY_LAST_TEMPLATE_KEY = 'tm-entra-group-naming-v2:lastTemplate';

    const OVERLAY_ID = `${PREFIX}-overlay`;
    const STYLE_ID = `${PREFIX}-style`;
    const BUTTON_CLASS = `${PREFIX}-open`;

    const OPS = [
        ['equals', 'Equals'],
        ['notEquals', 'Does not equal'],
        ['contains', 'Contains'],
        ['notContains', 'Does not contain'],
        ['startsWith', 'Starts with'],
        ['endsWith', 'Ends with'],
        ['oneOf', 'Is one of'],
        ['notOneOf', 'Is not one of'],
        ['empty', 'Is empty'],
        ['notEmpty', 'Is not empty'],
        ['regex', 'Matches regex']
    ];

    const SOURCE_TYPES = [
        ['previous', 'Previous segment'],
        ['segment', 'Specific previous segment'],
        ['prefix', 'Combined previous value']
    ];

    const whenNone = () => ({ mode: 'all', conditions: [] });

    const BUILTIN_TEMPLATES = [
        {
            id: 'intune-standard',
            name: 'Group - Intune Standard',
            surfaces: ['group'],
            separator: '-',
            segments: [
                { id:'g-intune-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'g-intune-membership', name:'Membership', type:'select', defaultValue:'STA', required:true,
                  options:[{value:'STA',label:'Static'},{value:'DYN',label:'Dynamic'}], when:whenNone() },
                { id:'g-intune-object', name:'Object type', type:'select', defaultValue:'DEV', required:true,
                  options:[{value:'DEV',label:'Device'},{value:'USR',label:'User'}], when:whenNone() },
                { id:'g-intune-purpose', name:'Purpose', type:'select', defaultValue:'APP', required:true,
                  options:[
                      {value:'APP',label:'Application'},
                      {value:'CONFIG',label:'Configuration'},
                      {value:'UPDATE',label:'Update'},
                      {value:'AUTOPILOT',label:'Autopilot'},
                      {value:'COMPLIANCE',label:'Compliance'},
                      {value:'EXCL',label:'Exclusion'},
                      {value:'RBAC',label:'RBAC'}
                  ], when:whenNone() },
                { id:'g-intune-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. 7-Zip, Ring1, Kiosk', when:whenNone() },
                { id:'g-intune-qualifier', name:'Qualifier', type:'text', defaultValue:'', required:false, placeholder:'Optional', when:whenNone() }
            ]
        },
        {
            id: 'defender-security',
            name: 'Group - Defender Security',
            surfaces: ['group'],
            separator: '-',
            segments: [
                { id:'g-def-service', name:'Service', type:'fixed', fixedValue:'Defender', required:true, when:whenNone() },
                { id:'g-def-membership', name:'Membership', type:'select', defaultValue:'STA', required:true,
                  options:[{value:'STA',label:'Static'},{value:'DYN',label:'Dynamic'}], when:whenNone() },
                { id:'g-def-object', name:'Object type', type:'select', defaultValue:'DEV', required:true,
                  options:[{value:'DEV',label:'Device'},{value:'USR',label:'User'}], when:whenNone() },
                { id:'g-def-area', name:'Security area', type:'select', defaultValue:'ASR', required:true,
                  options:[
                      {value:'AV',label:'Microsoft Defender Antivirus'},
                      {value:'ASR',label:'Attack Surface Reduction'},
                      {value:'EDR',label:'Endpoint Detection and Response'},
                      {value:'FW',label:'Firewall'},
                      {value:'NP',label:'Network Protection'},
                      {value:'WEB',label:'Web Protection'},
                      {value:'DC',label:'Device Control'},
                      {value:'WDAC',label:'Application Control / WDAC'},
                      {value:'EXPLOIT',label:'Exploit Protection'},
                      {value:'BASELINE',label:'Security Baseline'}
                  ], when:whenNone() },
                { id:'g-def-purpose', name:'Purpose', type:'select', defaultValue:'CONFIG', required:true,
                  options:[
                      {value:'CONFIG',label:'Configuration'},
                      {value:'EXCL',label:'Exclusion'},
                      {value:'PILOT',label:'Pilot'},
                      {value:'RING',label:'Ring'},
                      {value:'TEST',label:'Test'},
                      {value:'PROD',label:'Production'}
                  ], when:whenNone() },
                { id:'g-def-ring', name:'Ring', type:'select', defaultValue:'Ring1', required:true,
                  options:[
                      {value:'Test',label:'Test'},
                      {value:'Ring1',label:'Ring 1'},
                      {value:'Ring2',label:'Ring 2'},
                      {value:'Ring3',label:'Ring 3'},
                      {value:'Last',label:'Last'}
                  ],
                  when:{mode:'any',conditions:[
                      {sourceType:'segment',segmentId:'g-def-purpose',operator:'equals',value:'PILOT'},
                      {sourceType:'segment',segmentId:'g-def-purpose',operator:'equals',value:'RING'}
                  ]} },
                { id:'g-def-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. OfficeChildProcess, Developers', when:whenNone() },
                { id:'g-def-qualifier', name:'Qualifier', type:'text', defaultValue:'', required:false, placeholder:'Optional', when:whenNone() }
            ]
        },
        {
            id: 'entra-access',
            name: 'Group - Entra Access & Identity',
            surfaces: ['group'],
            separator: '-',
            segments: [
                { id:'g-entra-service', name:'Service', type:'fixed', fixedValue:'Entra', required:true, when:whenNone() },
                { id:'g-entra-membership', name:'Membership', type:'select', defaultValue:'STA', required:true,
                  options:[{value:'STA',label:'Static'},{value:'DYN',label:'Dynamic'}], when:whenNone() },
                { id:'g-entra-object', name:'Object type', type:'select', defaultValue:'USR', required:true,
                  options:[{value:'USR',label:'User'},{value:'DEV',label:'Device'}], when:whenNone() },
                { id:'g-entra-area', name:'Area', type:'select', defaultValue:'CA', required:true,
                  options:[
                      {value:'CA',label:'Conditional Access'},
                      {value:'RBAC',label:'Role Based Access'},
                      {value:'PIM',label:'Privileged Identity Management'},
                      {value:'AUTH',label:'Authentication'},
                      {value:'SSPR',label:'Self-service password reset'},
                      {value:'ACCESS',label:'Access assignment'},
                      {value:'LIFECYCLE',label:'Identity lifecycle'}
                  ], when:whenNone() },
                { id:'g-entra-purpose', name:'Purpose', type:'select', defaultValue:'ASSIGN', required:true,
                  options:[
                      {value:'ASSIGN',label:'Assignment'},
                      {value:'INCL',label:'Include'},
                      {value:'EXCL',label:'Exclude'},
                      {value:'PILOT',label:'Pilot'},
                      {value:'ADMIN',label:'Administrative scope'}
                  ], when:whenNone() },
                { id:'g-entra-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. MFA-Admins, BreakGlass, Pilot', when:whenNone() }
            ]
        },

        // Configuration Profiles
        {
            id: 'intune-config-profile',
            name: 'Intune - Configuration Profile',
            surfaces: ['configuration','generic'],
            separator: '-',
            segments: [
                { id:'cfg-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'cfg-kind', name:'Object type', type:'fixed', fixedValue:'CONFIG', required:true, when:whenNone() },
                { id:'cfg-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[
                      {value:'WIN',label:'Windows'},
                      {value:'MAC',label:'macOS'},
                      {value:'IOS',label:'iOS / iPadOS'},
                      {value:'AND',label:'Android'},
                      {value:'LNX',label:'Linux'},
                      {value:'MULTI',label:'Multi-platform'}
                  ], when:whenNone() },
                { id:'cfg-target', name:'Target', type:'select', defaultValue:'DEV', required:true,
                  options:[
                      {value:'DEV',label:'Device settings'},
                      {value:'USR',label:'User settings'},
                      {value:'BOTH',label:'Device and user'}
                  ], when:whenNone() },
                { id:'cfg-profiletype', name:'Profile type', type:'select', defaultValue:'SETTINGS', required:true,
                  options:[
                      {value:'SETTINGS',label:'Settings Catalog'},
                      {value:'ADMX',label:'Administrative Templates / ADMX'},
                      {value:'CUSTOM',label:'Custom / OMA-URI'},
                      {value:'RESTR',label:'Device Restrictions'},
                      {value:'KIOSK',label:'Kiosk'},
                      {value:'CERT',label:'Certificates'},
                      {value:'WIFI',label:'Wi-Fi'},
                      {value:'VPN',label:'VPN'},
                      {value:'EDGE',label:'Microsoft Edge'},
                      {value:'ONEDRIVE',label:'OneDrive'},
                      {value:'WHFB',label:'Windows Hello for Business'},
                      {value:'OTHER',label:'Other'}
                  ], when:whenNone() },
                { id:'cfg-area', name:'Area', type:'text', defaultValue:'', required:true, placeholder:'e.g. BitLocker, Explorer, OneDrive, Security', when:whenNone() },
                { id:'cfg-detail', name:'Detail', type:'text', defaultValue:'', required:false, placeholder:'Optional detail / scope', when:whenNone() }
            ]
        },

        // Endpoint Security
        {
            id: 'intune-endpoint-security',
            name: 'Intune - Endpoint Security Policy',
            surfaces: ['endpoint-security','generic'],
            separator: '-',
            segments: [
                { id:'sec-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'sec-kind', name:'Object type', type:'fixed', fixedValue:'SEC', required:true, when:whenNone() },
                { id:'sec-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[
                      {value:'WIN',label:'Windows'},
                      {value:'MAC',label:'macOS'},
                      {value:'LNX',label:'Linux'}
                  ], when:whenNone() },
                { id:'sec-area', name:'Security area', type:'select', defaultValue:'ASR', required:true,
                  options:[
                      {value:'AV',label:'Antivirus'},
                      {value:'ASR',label:'Attack Surface Reduction'},
                      {value:'EDR',label:'Endpoint Detection and Response'},
                      {value:'FW',label:'Firewall'},
                      {value:'DISK',label:'Disk Encryption'},
                      {value:'AC',label:'Account Protection'},
                      {value:'WDAC',label:'Application Control'},
                      {value:'DC',label:'Device Control'},
                      {value:'BASELINE',label:'Security Baseline'}
                  ], when:whenNone() },
                { id:'sec-scope', name:'Scope', type:'select', defaultValue:'DEV', required:true,
                  options:[{value:'DEV',label:'Device'},{value:'USR',label:'User'},{value:'BOTH',label:'Both'}], when:whenNone() },
                { id:'sec-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. Standard, Hardened, OfficeRules', when:whenNone() },
                { id:'sec-ring', name:'Ring / stage', type:'text', defaultValue:'', required:false, placeholder:'Optional: Pilot, Ring1, Prod', when:whenNone() }
            ]
        },

        // Compliance
        {
            id: 'intune-compliance',
            name: 'Intune - Compliance Policy',
            surfaces: ['compliance','generic'],
            separator: '-',
            segments: [
                { id:'comp-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'comp-kind', name:'Object type', type:'fixed', fixedValue:'COMP', required:true, when:whenNone() },
                { id:'comp-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[
                      {value:'WIN',label:'Windows'},
                      {value:'MAC',label:'macOS'},
                      {value:'IOS',label:'iOS / iPadOS'},
                      {value:'AND',label:'Android'},
                      {value:'LNX',label:'Linux'}
                  ], when:whenNone() },
                { id:'comp-area', name:'Area', type:'select', defaultValue:'BASE', required:true,
                  options:[
                      {value:'BASE',label:'Base compliance'},
                      {value:'SEC',label:'Security / hardening'},
                      {value:'UPDATE',label:'Windows Update'},
                      {value:'DEFENDER',label:'Microsoft Defender'},
                      {value:'ENCRYPT',label:'Encryption'},
                      {value:'CUSTOM',label:'Custom compliance'}
                  ], when:whenNone() },
                { id:'comp-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. NetworkHardening, BitLocker, 25H2', when:whenNone() }
            ]
        },

        // Remediations
        {
            id: 'intune-remediation',
            name: 'Intune - Remediation',
            surfaces: ['remediation','generic'],
            separator: '-',
            segments: [
                { id:'rem-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'rem-kind', name:'Object type', type:'fixed', fixedValue:'REMED', required:true, when:whenNone() },
                { id:'rem-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[{value:'WIN',label:'Windows'},{value:'MAC',label:'macOS'}], when:whenNone() },
                { id:'rem-scope', name:'Context', type:'select', defaultValue:'SYS', required:true,
                  options:[{value:'SYS',label:'System / device'},{value:'USR',label:'User'}], when:whenNone() },
                { id:'rem-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. Repair-AppX, Fix-Policy, Detect-Printer', when:whenNone() }
            ]
        },

        // Scripts
        {
            id: 'intune-script',
            name: 'Intune - Platform Script',
            surfaces: ['script','generic'],
            separator: '-',
            segments: [
                { id:'script-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'script-kind', name:'Object type', type:'fixed', fixedValue:'SCRIPT', required:true, when:whenNone() },
                { id:'script-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[{value:'WIN',label:'Windows PowerShell'},{value:'MAC',label:'macOS Shell'}], when:whenNone() },
                { id:'script-context', name:'Context', type:'select', defaultValue:'SYS', required:true,
                  options:[{value:'SYS',label:'System'},{value:'USR',label:'User'}], when:whenNone() },
                { id:'script-purpose', name:'Purpose', type:'select', defaultValue:'CONFIG', required:true,
                  options:[
                      {value:'CONFIG',label:'Configuration'},
                      {value:'INVENTORY',label:'Inventory'},
                      {value:'REPAIR',label:'Repair'},
                      {value:'MIGRATE',label:'Migration'},
                      {value:'CLEANUP',label:'Cleanup'}
                  ], when:whenNone() },
                { id:'script-detail', name:'Detail', type:'text', defaultValue:'', required:true, placeholder:'e.g. Configure-Routing, Cleanup-AppX', when:whenNone() }
            ]
        },

        // Applications
        {
            id: 'intune-app',
            name: 'Intune - Application',
            surfaces: ['app','generic'],
            separator: '-',
            segments: [
                { id:'app-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'app-kind', name:'Object type', type:'fixed', fixedValue:'APP', required:true, when:whenNone() },
                { id:'app-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[{value:'WIN',label:'Windows'},{value:'MAC',label:'macOS'},{value:'IOS',label:'iOS / iPadOS'},{value:'AND',label:'Android'}], when:whenNone() },
                { id:'app-type', name:'App type', type:'select', defaultValue:'WIN32', required:true,
                  options:[
                      {value:'WIN32',label:'Win32'},
                      {value:'STORE',label:'Microsoft Store'},
                      {value:'LOB',label:'Line-of-business'},
                      {value:'WEB',label:'Web link'},
                      {value:'PKG',label:'Package'}
                  ], when:whenNone() },
                { id:'app-name', name:'Application', type:'text', defaultValue:'', required:true, placeholder:'e.g. 7-Zip, CitrixWorkspace', when:whenNone() },
                { id:'app-qualifier', name:'Qualifier', type:'text', defaultValue:'', required:false, placeholder:'Optional: Prod, Pilot, x64', when:whenNone() }
            ]
        },

        // Updates
        {
            id: 'intune-update',
            name: 'Intune - Windows Update Policy',
            surfaces: ['update','generic'],
            separator: '-',
            segments: [
                { id:'upd-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'upd-kind', name:'Object type', type:'fixed', fixedValue:'UPDATE', required:true, when:whenNone() },
                { id:'upd-platform', name:'Platform', type:'fixed', fixedValue:'WIN', required:true, when:whenNone() },
                { id:'upd-type', name:'Update type', type:'select', defaultValue:'QUALITY', required:true,
                  options:[
                      {value:'QUALITY',label:'Quality updates'},
                      {value:'FEATURE',label:'Feature updates'},
                      {value:'DRIVER',label:'Driver updates'},
                      {value:'EXPEDITE',label:'Expedited updates'},
                      {value:'RING',label:'Update ring'}
                  ], when:whenNone() },
                { id:'upd-ring', name:'Ring', type:'select', defaultValue:'Ring1', required:true,
                  options:[
                      {value:'Test',label:'Test'},
                      {value:'Ring1',label:'Ring 1'},
                      {value:'Ring2',label:'Ring 2'},
                      {value:'Ring3',label:'Ring 3'},
                      {value:'Last',label:'Last'}
                  ], when:whenNone() },
                { id:'upd-detail', name:'Detail', type:'text', defaultValue:'', required:false, placeholder:'e.g. 25H2, Ring1, Kiosk', when:whenNone() }
            ]
        },

        // Assignment filters
        {
            id: 'intune-filter',
            name: 'Intune - Assignment Filter',
            surfaces: ['filter','generic'],
            separator: '-',
            segments: [
                { id:'flt-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'flt-kind', name:'Object type', type:'fixed', fixedValue:'FILTER', required:true, when:whenNone() },
                { id:'flt-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[{value:'WIN',label:'Windows'},{value:'MAC',label:'macOS'},{value:'IOS',label:'iOS / iPadOS'},{value:'AND',label:'Android'}], when:whenNone() },
                { id:'flt-purpose', name:'Purpose', type:'text', defaultValue:'', required:true, placeholder:'e.g. Corporate, Lenovo, Kiosk, VPN', when:whenNone() }
            ]
        }
,
        // Sample policy templates for common Intune naming conventions.
        {
            id: 'sample-defender-policy',
            name: 'Sample - Defender Policy',
            surfaces: ['endpoint-security','generic'],
            separator: '-',
            segments: [
                { id:'sample-def-service', name:'Service', type:'fixed', fixedValue:'Defender', required:true, when:whenNone() },
                { id:'sample-def-pol', name:'Object type', type:'fixed', fixedValue:'POL', required:true, when:whenNone() },
                { id:'sample-def-area', name:'Security area', type:'select', defaultValue:'ASR', required:true,
                  options:[
                      {value:'ASR',label:'Attack Surface Reduction'},
                      {value:'AV',label:'Antivirus'},
                      {value:'EDR',label:'Endpoint Detection and Response'},
                      {value:'FW',label:'Firewall'},
                      {value:'USB',label:'Device Control / USB'},
                      {value:'WDAC',label:'Application Control / WDAC'},
                      {value:'BITLOCKER',label:'BitLocker'},
                      {value:'LAPS',label:'Windows LAPS'},
                      {value:'BASELINE',label:'Security Baseline'}
                  ], when:whenNone() },
                { id:'sample-def-subarea', name:'Subarea / Rule family', type:'text', defaultValue:'', required:false,
                  placeholder:'e.g. USB, UnknownExecutables, Office', when:whenNone() },
                { id:'sample-def-ring-label', name:'Ring label', type:'fixed', fixedValue:'Ring', required:true, when:whenNone() },
                { id:'sample-def-ring', name:'Ring', type:'select', defaultValue:'3', required:true,
                  options:[
                      {value:'0',label:'Ring 0'},
                      {value:'1',label:'Ring 1'},
                      {value:'2',label:'Ring 2'},
                      {value:'3',label:'Ring 3'}
                  ], when:whenNone() },
                { id:'sample-def-stage', name:'Stage', type:'select', defaultValue:'Production', required:true,
                  options:[
                      {value:'Development',label:'Development'},
                      {value:'Test',label:'Test'},
                      {value:'Pilot',label:'Pilot'},
                      {value:'Production',label:'Production'}
                  ], when:whenNone() },
                { id:'sample-def-scope', name:'Scope', type:'text', defaultValue:'', required:false,
                  placeholder:'e.g. Ring1, BusinessUnit, Compliance', when:whenNone() },
                { id:'sample-def-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'Optional exception / purpose', when:whenNone() }
            ]
        },
        {
            id: 'sample-autopilot-domainjoin',
            name: 'Sample - Autopilot Domain Join',
            surfaces: ['configuration','generic'],
            separator: '-',
            segments: [
                { id:'sample-ap-service', name:'Service', type:'fixed', fixedValue:'Autopilot', required:true, when:whenNone() },
                { id:'sample-ap-purpose', name:'Purpose', type:'fixed', fixedValue:'DomainJoin', required:true, when:whenNone() },
                { id:'sample-ap-scope', name:'Scope', type:'text', defaultValue:'', required:false,
                  placeholder:'e.g. BusinessUnitA, Pilot, Shared', when:whenNone() }
            ]
        },
        {
            id: 'sample-config-policy',
            name: 'Sample - Intune Configuration Policy',
            surfaces: ['configuration','generic'],
            separator: '-',
            segments: [
                { id:'sample-cfg-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'sample-cfg-pol', name:'Object type', type:'fixed', fixedValue:'POL', required:true, when:whenNone() },
                { id:'sample-cfg-type', name:'Policy type', type:'fixed', fixedValue:'CONFIG', required:true, when:whenNone() },
                { id:'sample-cfg-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[
                      {value:'WIN',label:'Windows'},
                      {value:'MAC',label:'macOS'},
                      {value:'IOS',label:'iOS / iPadOS'},
                      {value:'AND',label:'Android'},
                      {value:'LNX',label:'Linux'}
                  ], when:whenNone() },
                { id:'sample-cfg-context', name:'Context', type:'select', defaultValue:'DEV', required:true,
                  options:[
                      {value:'DEV',label:'Device'},
                      {value:'USR',label:'User'},
                      {value:'BOTH',label:'Device and user'}
                  ], when:whenNone() },
                { id:'sample-cfg-area', name:'Area', type:'text', defaultValue:'', required:true,
                  placeholder:'e.g. Edge, Kiosk, DeliveryOptimization, NTP, WinRM', when:whenNone() },
                { id:'sample-cfg-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'Optional setting / scope / exception', when:whenNone() }
            ]
        },
        {
            id: 'sample-kiosk-policy',
            name: 'Sample - Kiosk Policy',
            surfaces: ['configuration','generic'],
            separator: '-',
            segments: [
                { id:'sample-kiosk-service', name:'Service', type:'fixed', fixedValue:'Intune', required:true, when:whenNone() },
                { id:'sample-kiosk-pol', name:'Object type', type:'fixed', fixedValue:'POL', required:true, when:whenNone() },
                { id:'sample-kiosk-purpose', name:'Purpose', type:'fixed', fixedValue:'KIOSK', required:true, when:whenNone() },
                { id:'sample-kiosk-platform', name:'Platform', type:'fixed', fixedValue:'WIN', required:true, when:whenNone() },
                { id:'sample-kiosk-scope', name:'Scope', type:'text', defaultValue:'', required:true,
                  placeholder:'e.g. RegionA, RegionB, Shared', when:whenNone() },
                { id:'sample-kiosk-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'e.g. SharedDisplay, AlwaysOn', when:whenNone() }
            ]
        },
        {
            id: 'sample-security-policy',
            name: 'Sample - Windows Security Policy',
            surfaces: ['endpoint-security','configuration','generic'],
            separator: '-',
            segments: [
                { id:'sample-sec-service', name:'Service', type:'fixed', fixedValue:'Security', required:true, when:whenNone() },
                { id:'sample-sec-pol', name:'Object type', type:'fixed', fixedValue:'POL', required:true, when:whenNone() },
                { id:'sample-sec-area', name:'Area', type:'select', defaultValue:'LAPS', required:true,
                  options:[
                      {value:'LAPS',label:'Windows LAPS'},
                      {value:'BITLOCKER',label:'BitLocker'},
                      {value:'LOCALADMIN',label:'Local administrator membership'},
                      {value:'CERT',label:'Certificates'}
                  ], when:whenNone() },
                { id:'sample-sec-join', name:'Join type', type:'select', defaultValue:'HybridJoined', required:false,
                  options:[
                      {value:'HybridJoined',label:'Hybrid joined'},
                      {value:'EntraJoined',label:'Entra joined'},
                      {value:'All',label:'All'}
                  ], when:whenNone() },
                { id:'sample-sec-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'Optional purpose / account / certificate', when:whenNone() }
            ]
        },
        {
            id: 'sample-m365-policy',
            name: 'Sample - M365 Office Policy',
            surfaces: ['configuration','generic'],
            separator: '-',
            segments: [
                { id:'sample-m365-service', name:'Service', type:'fixed', fixedValue:'M365', required:true, when:whenNone() },
                { id:'sample-m365-product', name:'Product', type:'fixed', fixedValue:'Office', required:true, when:whenNone() },
                { id:'sample-m365-context', name:'Context', type:'select', defaultValue:'DEV', required:true,
                  options:[
                      {value:'DEV',label:'Computer / Device'},
                      {value:'USR',label:'User'}
                  ], when:whenNone() },
                { id:'sample-m365-purpose', name:'Purpose', type:'text', defaultValue:'Policies', required:true,
                  placeholder:'e.g. Policies, Kiosk, Security', when:whenNone() },
                { id:'sample-m365-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'Optional', when:whenNone() }
            ]
        },
        {
            id: 'sample-unified-policy',
            name: 'Sample - Unified Intune Policy',
            surfaces: ['configuration','endpoint-security','compliance','update','filter','generic'],
            separator: '-',
            segments: [
                { id:'sample-u-service', name:'Service', type:'select', defaultValue:'Intune', required:true,
                  options:[
                      {value:'Intune',label:'Intune'},
                      {value:'Defender',label:'Defender'},
                      {value:'Autopilot',label:'Autopilot'},
                      {value:'Security',label:'Security'},
                      {value:'M365',label:'Microsoft 365'}
                  ], when:whenNone() },
                { id:'sample-u-pol', name:'Object type', type:'fixed', fixedValue:'POL', required:true, when:whenNone() },
                { id:'sample-u-type', name:'Policy type', type:'select', defaultValue:'CONFIG', required:true,
                  options:[
                      {value:'CONFIG',label:'Configuration'},
                      {value:'SEC',label:'Endpoint Security'},
                      {value:'COMP',label:'Compliance'},
                      {value:'UPDATE',label:'Updates'},
                      {value:'KIOSK',label:'Kiosk'},
                      {value:'CERT',label:'Certificate'},
                      {value:'NETWORK',label:'Network'},
                      {value:'INVENTORY',label:'Inventory'}
                  ], when:whenNone() },
                { id:'sample-u-platform', name:'Platform', type:'select', defaultValue:'WIN', required:true,
                  options:[
                      {value:'WIN',label:'Windows'},
                      {value:'MAC',label:'macOS'},
                      {value:'IOS',label:'iOS / iPadOS'},
                      {value:'AND',label:'Android'},
                      {value:'LNX',label:'Linux'}
                  ], when:whenNone() },
                { id:'sample-u-context', name:'Context', type:'select', defaultValue:'DEV', required:false,
                  options:[
                      {value:'DEV',label:'Device'},
                      {value:'USR',label:'User'},
                      {value:'BOTH',label:'Both'}
                  ], when:whenNone() },
                { id:'sample-u-area', name:'Area', type:'text', defaultValue:'', required:true,
                  placeholder:'e.g. Edge, ASR, BitLocker, DeliveryOptimization', when:whenNone() },
                { id:'sample-u-detail', name:'Detail', type:'text', defaultValue:'', required:false,
                  placeholder:'Optional scope / purpose / exception', when:whenNone() }
            ]
        }
    ];

    const SURFACE_DEFAULT_TEMPLATE = {
        group: 'intune-standard',
        configuration: 'intune-config-profile',
        'endpoint-security': 'intune-endpoint-security',
        compliance: 'intune-compliance',
        remediation: 'intune-remediation',
        script: 'intune-script',
        app: 'intune-app',
        update: 'intune-update',
        filter: 'intune-filter'
    };

    let state = null;
    let currentTarget = null;
    let lastCandidate = null;
    const boundInputs = new WeakSet();

    function clone(v) { return JSON.parse(JSON.stringify(v)); }
    function norm(v) { return String(v ?? '').trim().toLowerCase(); }
    function newId(prefix='id') { return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,8)}`; }
    function clean(v) { return String(v ?? '').trim().replace(/^[-_\s]+|[-_\s]+$/g, ''); }
    function isVisible(el) {
        if (!el || !(el instanceof Element)) return false;
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden';
    }

    function loadTemplates() {
        try {
            let raw = GM_getValue(STORAGE_KEY, '');
            if (!raw) {
                raw = GM_getValue(LEGACY_STORAGE_KEY, '');
                const legacyLast = GM_getValue(LEGACY_LAST_TEMPLATE_KEY, '');
                if (legacyLast && !GM_getValue(LAST_TEMPLATE_KEY, '')) {
                    GM_setValue(LAST_TEMPLATE_KEY, legacyLast);
                }
            }

            let templates = [];
            if (raw) {
                const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
                if (Array.isArray(parsed)) templates = parsed;
            }

            if (!templates.length) templates = BUILTIN_TEMPLATES.map(clone);

            const installed = Number(GM_getValue(BUILTIN_VERSION_KEY, 0)) || 0;
            if (installed < BUILTIN_VERSION) {
                const ids = new Set(templates.map(t => t.id));
                for (const builtin of BUILTIN_TEMPLATES) {
                    if (!ids.has(builtin.id)) templates.push(clone(builtin));
                }
                GM_setValue(STORAGE_KEY, JSON.stringify(templates));
                GM_setValue(BUILTIN_VERSION_KEY, BUILTIN_VERSION);
            }

            return templates;
        } catch (error) {
            console.warn('[Naming Designer] Failed to load templates.', error);
            return BUILTIN_TEMPLATES.map(clone);
        }
    }

    function saveTemplates() {
        if (!state) return;
        GM_setValue(STORAGE_KEY, JSON.stringify(state.templates));
    }

    function getPortalSignature() {
        const modules = [...document.querySelectorAll('[data-requiremodule]')]
            .map(x => x.getAttribute('data-requiremodule') || '')
            .join(' ')
            .toLowerCase();

        const title = [
            document.querySelector('#__bladeTitleMain')?.textContent || '',
            document.querySelector('#__bladeSubtitle')?.textContent || '',
            document.title || ''
        ].join(' ').toLowerCase();

        const text = (document.body?.innerText || '').slice(0, 12000).toLowerCase();
        return { modules, title, text };
    }

    function detectSurface() {
        const { modules, title, text } = getPortalSignature();
        const all = `${modules} ${title} ${text}`;

        if (modules.includes('addgroup.reactview') || text.includes('group name')) return 'group';

        if (/(endpoint security|attack surface reduction|antivirus|endpoint detection and response|disk encryption|account protection|security baseline)/.test(all)) {
            return 'endpoint-security';
        }

        if (/(compliance policy|custom compliance|compliance settings)/.test(all)) return 'compliance';
        if (/(remediation|proactive remediation|remediations)/.test(all)) return 'remediation';
        if (/(assignment filter|filters for devices|filter rule)/.test(all)) return 'filter';
        if (/(feature update|quality update|driver update|update ring|expedited update|windows update)/.test(all)) return 'update';
        if (/(win32 app|add app|app information|line-of-business app|microsoft store app)/.test(all)) return 'app';
        if (/(platform script|powershell script|shell script|scripts and remediations)/.test(all)) return 'script';
        if (/(settings catalog|configuration profile|configuration settings|device restrictions|administrative templates|oma-uri)/.test(all)) return 'configuration';

        return 'generic';
    }

    function labelTextFor(input) {
        if (!input) return '';
        if (input.id) {
            const label = document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
            if (label) return (label.textContent || '').replace(/\*/g, '').trim();
        }
        const field = input.closest('.fui-Field, .ms-TextField, [role="group"], div');
        const label = field?.querySelector('label');
        return (label?.textContent || '').replace(/\*/g, '').trim();
    }

    function candidateScore(input) {
        if (!isVisible(input) || input.disabled || input.readOnly) return -999;
        if (input.closest(`#${OVERLAY_ID}`)) return -999;
        if (input.type && !['text','search',''].includes(input.type)) return -999;
        if (input.getAttribute('role') === 'searchbox' || input.type === 'search') return -999;

        const placeholder = norm(input.getAttribute('placeholder'));
        const aria = norm(input.getAttribute('aria-label'));
        const name = norm(input.getAttribute('name'));
        const label = norm(labelTextFor(input));

        if (placeholder === 'enter the name of the group' || label === 'group name') return 1000;

        let score = 0;
        if (label === 'name') score += 550;
        if (aria === 'name') score += 300;
        if (/^(enter )?(a )?name$/.test(placeholder)) score += 250;
        if (name === 'name' || name === 'displayname') score += 180;

        // Basics pages in Intune commonly pair Name + Description.
        const fieldRoot = input.closest('form, .fui-FluentProvider, #root') || document;
        const rootText = norm(fieldRoot.innerText || '');
        if (rootText.includes('description')) score += 100;
        if (rootText.includes('next') || rootText.includes('create') || rootText.includes('save')) score += 60;

        return score;
    }

    function findNamingTarget() {
        const inputs = [...document.querySelectorAll('input')]
            .map(input => ({ input, score: candidateScore(input) }))
            .filter(x => x.score >= 400)
            .sort((a,b) => b.score - a.score);

        if (!inputs.length) return null;
        const input = inputs[0].input;
        return { input, surface: detectSurface() };
    }

    function setReactValue(input, value) {
        if (!input) return;
        const descriptor =
            Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), 'value') ||
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

        if (descriptor?.set) descriptor.set.call(input, value);
        else input.value = value;

        input.dispatchEvent(new Event('input', { bubbles:true }));
        input.dispatchEvent(new Event('change', { bubbles:true }));
        input.focus();
        input.dispatchEvent(new Event('blur', { bubbles:true }));
    }

    function ensureStyle() {
        if (document.getElementById(STYLE_ID)) return;
        const style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent = `
.${BUTTON_CLASS}{
  margin-top:7px;height:30px;padding:0 12px;border:1px solid var(--colorControlBorder,#8a8886);
  border-radius:2px;background:var(--colorButtonBackgroundSecondary,#fff);
  color:var(--colorButtonForegroundSecondary,#0078d4);font:600 13px "Segoe UI",sans-serif;cursor:pointer
}
.${BUTTON_CLASS}:hover{background:var(--colorButtonBackgroundSecondaryHover,#f3f2f1)}
#${OVERLAY_ID}{position:fixed;inset:0;z-index:2147483646;background:rgba(0,0,0,.38);display:flex;align-items:center;justify-content:center;padding:20px;box-sizing:border-box;font:13px "Segoe UI",sans-serif}
.${PREFIX}-panel{width:min(1040px,calc(100vw - 40px));max-height:calc(100vh - 40px);display:flex;flex-direction:column;background:var(--colorContainerBackgroundPrimary,#fff);color:var(--colorTextPrimary,#242424);border:1px solid var(--colorContainerBorderSecondary,#d1d1d1);box-shadow:0 16px 48px rgba(0,0,0,.35);border-radius:4px;overflow:hidden}
.${PREFIX}-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--colorContainerBorderPrimary,#ddd);font-size:17px;font-weight:600}
.${PREFIX}-close{border:0;background:transparent;color:inherit;font-size:20px;cursor:pointer}
.${PREFIX}-tabs{display:flex;gap:4px;padding:8px 12px 0;border-bottom:1px solid var(--colorContainerBorderPrimary,#ddd)}
.${PREFIX}-tab{padding:8px 12px;border:0;border-bottom:2px solid transparent;background:transparent;color:inherit;cursor:pointer}
.${PREFIX}-tab.active{border-bottom-color:var(--colorTextBrand,#0078d4);font-weight:600}
.${PREFIX}-body{padding:16px;overflow:auto}
.${PREFIX}-row{display:flex;gap:10px;align-items:end;margin-bottom:10px;flex-wrap:wrap}
.${PREFIX}-field{display:flex;flex-direction:column;gap:4px;min-width:160px;flex:1}
.${PREFIX}-field label{font-size:12px;color:var(--colorTextSecondary,#666)}
.${PREFIX}-input,.${PREFIX}-select,.${PREFIX}-textarea{width:100%;min-height:32px;padding:6px 8px;border:1px solid var(--colorControlBorder,#8a8886);border-radius:2px;background:var(--colorControlBackground,#fff);color:var(--colorTextPrimary,#242424);font:inherit;box-sizing:border-box}
.${PREFIX}-textarea{min-height:90px;resize:vertical}
.${PREFIX}-btn{min-height:32px;padding:5px 12px;border:1px solid var(--colorControlBorder,#8a8886);border-radius:2px;background:var(--colorButtonBackgroundSecondary,#fff);color:var(--colorButtonForegroundSecondary,#0078d4);font:inherit;cursor:pointer;white-space:nowrap}
.${PREFIX}-btn.primary{background:var(--colorButtonBackgroundPrimary,#0078d4);border-color:var(--colorButtonBackgroundPrimary,#0078d4);color:var(--colorButtonForegroundPrimary,#fff);font-weight:600}
.${PREFIX}-btn.danger{color:var(--colorTextError,#a4262c)}
.${PREFIX}-preview{margin:14px 0;padding:12px;border:1px solid var(--colorContainerBorderPrimary,#ddd);background:var(--colorContainerBackgroundSecondary,rgba(0,0,0,.04));border-radius:3px}
.${PREFIX}-preview-name{font:15px Consolas,monospace;word-break:break-all;margin-top:4px}
.${PREFIX}-muted{font-size:12px;color:var(--colorTextSecondary,#666)}
.${PREFIX}-error{font-size:12px;color:var(--colorTextError,#a4262c)}
.${PREFIX}-card{border:1px solid var(--colorContainerBorderPrimary,#ddd);padding:12px;border-radius:4px;margin:12px 0}
.${PREFIX}-card-title{display:flex;align-items:center;justify-content:space-between;font-weight:600;margin-bottom:10px}
.${PREFIX}-condition{display:grid;grid-template-columns:150px 1fr 150px 1fr 36px;gap:6px;align-items:end;margin-top:6px}
.${PREFIX}-footer{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 16px;border-top:1px solid var(--colorContainerBorderPrimary,#ddd)}
.${PREFIX}-surface{padding:7px 9px;margin-bottom:12px;border-left:3px solid var(--colorControlBackgroundBrand,#0078d4);background:var(--colorContainerBackgroundSecondary,rgba(0,0,0,.04))}
@media(max-width:760px){.${PREFIX}-condition{grid-template-columns:1fr}}
`;
        document.head.appendChild(style);
    }

    function injectButton(target) {
        const input = target?.input;
        if (!input || boundInputs.has(input)) return;
        ensureStyle();

        const shell = input.closest('.fui-Input, .ms-TextField-fieldGroup') || input.parentElement;
        if (!shell) return;

        const button = document.createElement('button');
        button.type = 'button';
        button.className = BUTTON_CLASS;
        button.textContent = 'Naming Designer';
        button.title = `Open naming templates (${target.surface})`;
        button.dataset.surface = target.surface;

        button.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
            currentTarget = { input, surface: detectSurface() };
            openDesigner();
        });

        shell.insertAdjacentElement('afterend', button);
        boundInputs.add(input);
        input.dataset.tmNamingDesigner = 'bound';

        console.info('[Naming Designer] Name field detected.', {
            version: VERSION,
            surface: target.surface,
            label: labelTextFor(input),
            input
        });
    }

    function valuesFor(template) {
        const values = {};
        for (const s of template.segments || []) {
            values[s.id] = s.type === 'fixed' ? (s.fixedValue || '') : (s.defaultValue || '');
        }
        return values;
    }

    function sourceValue(c, index, values, template) {
        if (c.sourceType === 'previous') {
            const s = template.segments[index - 1];
            return s ? values[s.id] ?? (s.fixedValue || '') : '';
        }

        if (c.sourceType === 'prefix') {
            const parts = [];
            for (let i = 0; i < index; i++) {
                const s = template.segments[i];
                if (!segmentVisible(s, i, values, template)) continue;
                const v = clean(s.type === 'fixed' ? s.fixedValue : values[s.id]);
                if (v) parts.push(v);
            }
            return parts.join(template.separator || '-');
        }

        const s = template.segments.find(x => x.id === c.segmentId);
        if (!s) return '';
        return s.type === 'fixed' ? (s.fixedValue || '') : (values[s.id] ?? '');
    }

    function conditionMatches(c, index, values, template) {
        const actual = String(sourceValue(c,index,values,template) ?? '');
        const expected = String(c.value ?? '');

        switch(c.operator) {
            case 'equals': return norm(actual) === norm(expected);
            case 'notEquals': return norm(actual) !== norm(expected);
            case 'contains': return norm(actual).includes(norm(expected));
            case 'notContains': return !norm(actual).includes(norm(expected));
            case 'startsWith': return norm(actual).startsWith(norm(expected));
            case 'endsWith': return norm(actual).endsWith(norm(expected));
            case 'oneOf': return expected.split(/[;,\n]/).map(norm).filter(Boolean).includes(norm(actual));
            case 'notOneOf': return !expected.split(/[;,\n]/).map(norm).filter(Boolean).includes(norm(actual));
            case 'empty': return !actual.trim();
            case 'notEmpty': return !!actual.trim();
            case 'regex':
                try { return new RegExp(expected,'i').test(actual); }
                catch { return false; }
            default: return false;
        }
    }

    function segmentVisible(segment, index, values, template) {
        const when = segment.when || whenNone();
        const conditions = Array.isArray(when.conditions) ? when.conditions : [];
        if (!conditions.length) return true;
        const results = conditions.map(c => conditionMatches(c,index,values,template));
        return when.mode === 'any' ? results.some(Boolean) : results.every(Boolean);
    }

    function buildName(template, values) {
        const parts = [];
        const errors = [];

        (template.segments || []).forEach((s,i) => {
            if (!segmentVisible(s,i,values,template)) return;
            const raw = s.type === 'fixed' ? s.fixedValue : values[s.id];
            const v = clean(raw);

            if (s.required && !v) errors.push(`${s.name} is required.`);
            if (v) parts.push(v);
        });

        return { name: parts.join(template.separator || '-'), errors };
    }

    function field(label, control) {
        const wrap = document.createElement('div');
        wrap.className = `${PREFIX}-field`;
        const l = document.createElement('label');
        l.textContent = label;
        wrap.append(l, control);
        return wrap;
    }

    function makeInput(value,onChange,placeholder='') {
        const el = document.createElement('input');
        el.className = `${PREFIX}-input`;
        el.value = value ?? '';
        el.placeholder = placeholder;
        el.addEventListener('input', () => onChange(el.value));
        return el;
    }

    function makeSelect(options,value,onChange) {
        const el = document.createElement('select');
        el.className = `${PREFIX}-select`;
        for (const [v,l] of options) {
            const o = document.createElement('option');
            o.value = v;
            o.textContent = l;
            o.selected = String(v) === String(value ?? '');
            el.appendChild(o);
        }
        el.addEventListener('change', () => onChange(el.value));
        return el;
    }

    function makeButton(text,handler,cls='') {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = `${PREFIX}-btn ${cls}`.trim();
        b.textContent = text;
        b.addEventListener('click',handler);
        return b;
    }

    function currentTemplate() {
        return state.templates.find(t => t.id === state.templateId) || state.templates[0];
    }

    function preferredTemplateId(templates, surface) {
        const preferred = SURFACE_DEFAULT_TEMPLATE[surface];
        if (preferred && templates.some(t => t.id === preferred)) return preferred;

        const last = GM_getValue(LAST_TEMPLATE_KEY,'');
        if (last && templates.some(t => t.id === last)) return last;

        return templates[0]?.id || '';
    }

    function render() {
        const panel = document.querySelector(`#${OVERLAY_ID} .${PREFIX}-panel`);
        if (!panel || !state) return;

        panel.querySelectorAll(`.${PREFIX}-tab`).forEach(t =>
            t.classList.toggle('active',t.dataset.tab === state.tab)
        );

        const body = panel.querySelector(`.${PREFIX}-body`);
        body.replaceChildren();

        if (state.tab === 'builder') renderBuilder(body);
        else renderDesigner(body);

        renderFooter();
    }

    function renderBuilder(body) {
        const template = currentTemplate();
        if (!template) return;
        if (!state.values[template.id]) state.values[template.id] = valuesFor(template);
        const values = state.values[template.id];

        const surface = document.createElement('div');
        surface.className = `${PREFIX}-surface`;
        surface.textContent = `Detected surface: ${state.surface}`;
        body.append(surface);

        const row = document.createElement('div');
        row.className = `${PREFIX}-row`;

        // Surface-related templates first, but all remain available.
        const surfaceTemplates = state.templates
            .map(t => {
                const related = !t.surfaces || t.surfaces.includes(state.surface) || t.surfaces.includes('generic');
                return { t, related };
            })
            .sort((a,b) => Number(b.related) - Number(a.related));

        row.append(field('Template', makeSelect(
            surfaceTemplates.map(x => [x.t.id, `${x.related ? '★ ' : ''}${x.t.name}`]),
            template.id,
            v => {
                state.templateId = v;
                GM_setValue(LAST_TEMPLATE_KEY,v);
                render();
            }
        )));

        row.append(makeButton('Edit template', () => {
            state.tab = 'designer';
            render();
        }));

        body.append(row);

        (template.segments || []).forEach((s,i) => {
            if (!segmentVisible(s,i,values,template)) return;

            let control;
            if (s.type === 'fixed') {
                control = makeInput(s.fixedValue || '', () => {});
                control.disabled = true;
            } else if (s.type === 'select') {
                const opts = (s.options || []).map(o => [o.value,o.label || o.value]);
                if (!opts.some(o => o[0] === values[s.id])) values[s.id] = opts[0]?.[0] || '';
                control = makeSelect(opts,values[s.id],v => {
                    values[s.id] = v;
                    render();
                });
            } else {
                control = makeInput(values[s.id],v => {
                    values[s.id] = v;
                    updatePreview();
                },s.placeholder || '');
            }

            body.append(field(`${s.name}${s.required ? ' *' : ''}`,control));
        });

        const preview = document.createElement('div');
        preview.className = `${PREFIX}-preview`;
        preview.dataset.preview = '1';
        body.append(preview);
        updatePreview();
    }

    function updatePreview() {
        const p = document.querySelector(`#${OVERLAY_ID} [data-preview="1"]`);
        if (!p || !state) return;

        const t = currentTemplate();
        const result = buildName(t,state.values[t.id] || {});

        p.replaceChildren();

        const label = document.createElement('div');
        label.className = `${PREFIX}-muted`;
        label.textContent = 'Live preview';

        const name = document.createElement('div');
        name.className = `${PREFIX}-preview-name`;
        name.textContent = result.name || '(empty)';

        const status = document.createElement('div');
        status.style.marginTop = '6px';
        status.className = result.errors.length ? `${PREFIX}-error` : `${PREFIX}-muted`;
        status.textContent = result.errors.length
            ? result.errors.join(' | ')
            : `${result.name.length} / 256 characters`;

        p.append(label,name,status);
    }

    function conditionEditor(template,segment,index) {
        const wrap = document.createElement('div');
        segment.when ||= whenNone();
        segment.when.conditions ||= [];

        const top = document.createElement('div');
        top.className = `${PREFIX}-row`;

        top.append(field('Show this segment when',makeSelect(
            [['all','Match ALL conditions'],['any','Match ANY condition']],
            segment.when.mode || 'all',
            v => { segment.when.mode = v; saveTemplates(); }
        )));

        top.append(makeButton('+ Add condition',() => {
            segment.when.conditions.push({
                sourceType: index > 0 ? 'previous' : 'prefix',
                segmentId:'',
                operator:'equals',
                value:''
            });
            saveTemplates();
            render();
        }));

        wrap.append(top);

        segment.when.conditions.forEach((c,ci) => {
            const row = document.createElement('div');
            row.className = `${PREFIX}-condition`;

            row.append(field('Source',makeSelect(
                SOURCE_TYPES,
                c.sourceType || 'previous',
                v => { c.sourceType = v; saveTemplates(); render(); }
            )));

            let src;
            if (c.sourceType === 'segment') {
                const prior = template.segments.slice(0,index).map(s => [s.id,s.name]);
                src = makeSelect(
                    prior.length ? prior : [['','(none)']],
                    c.segmentId || prior[0]?.[0] || '',
                    v => { c.segmentId = v; saveTemplates(); }
                );
            } else {
                src = makeInput(
                    c.sourceType === 'previous' ? 'Immediate previous segment' : 'All visible previous values',
                    () => {}
                );
                src.disabled = true;
            }

            row.append(field('Segment',src));
            row.append(field('Operator',makeSelect(
                OPS,
                c.operator || 'equals',
                v => { c.operator = v; saveTemplates(); render(); }
            )));

            const val = makeInput(c.value || '',v => {
                c.value = v;
                saveTemplates();
            },['oneOf','notOneOf'].includes(c.operator) ? 'A, B, C' : 'Value');

            if (['empty','notEmpty'].includes(c.operator)) val.disabled = true;

            row.append(field('Value',val));
            row.append(makeButton('×',() => {
                segment.when.conditions.splice(ci,1);
                saveTemplates();
                render();
            },'danger'));

            wrap.append(row);
        });

        return wrap;
    }

    function renderDesigner(body) {
        const template = currentTemplate();
        if (!template) return;

        const top = document.createElement('div');
        top.className = `${PREFIX}-row`;

        top.append(field('Template name',makeInput(template.name,v => {
            template.name = v;
            saveTemplates();
        })));

        top.append(field('Separator',makeInput(template.separator || '-',v => {
            template.separator = v;
            saveTemplates();
        })));

        top.append(makeButton('+ New template',() => {
            const t = { id:newId('template'), name:'New Template', surfaces:['generic'], separator:'-', segments:[] };
            state.templates.push(t);
            state.templateId = t.id;
            state.values[t.id] = {};
            saveTemplates();
            render();
        }));

        top.append(makeButton('Duplicate',() => {
            const t = clone(template);
            t.id = newId('template');
            t.name += ' Copy';

            const idMap = new Map();
            for (const s of t.segments || []) {
                const old = s.id;
                s.id = newId('segment');
                idMap.set(old,s.id);
            }
            for (const s of t.segments || []) {
                for (const c of s.when?.conditions || []) {
                    if (c.segmentId && idMap.has(c.segmentId)) c.segmentId = idMap.get(c.segmentId);
                }
            }

            state.templates.push(t);
            state.templateId = t.id;
            state.values[t.id] = valuesFor(t);
            saveTemplates();
            render();
        }));

        body.append(top);

        const toolbar = document.createElement('div');
        toolbar.className = `${PREFIX}-row`;

        toolbar.append(makeButton('+ Add segment',() => {
            template.segments ||= [];
            template.segments.push({
                id:newId('segment'),
                name:'New segment',
                type:'text',
                defaultValue:'',
                required:false,
                when:whenNone()
            });
            saveTemplates();
            render();
        },'primary'));

        toolbar.append(makeButton('Export JSON',exportJson));
        toolbar.append(makeButton('Import JSON',importJson));
        toolbar.append(makeButton('Restore built-ins',restoreBuiltins));
        toolbar.append(makeButton('Delete template',() => {
            if (state.templates.length <= 1) return;
            if (!confirm(`Delete template "${template.name}"?`)) return;

            state.templates = state.templates.filter(t => t.id !== template.id);
            state.templateId = state.templates[0].id;
            saveTemplates();
            render();
        },'danger'));

        body.append(toolbar);

        const hint = document.createElement('div');
        hint.className = `${PREFIX}-muted`;
        hint.textContent =
            'Segment count is unlimited. Conditions can reference the previous segment, any specific segment to the left, or the complete visible prefix.';
        body.append(hint);

        (template.segments || []).forEach((s,index) => {
            const card = document.createElement('div');
            card.className = `${PREFIX}-card`;

            const title = document.createElement('div');
            title.className = `${PREFIX}-card-title`;

            const name = document.createElement('span');
            name.textContent = `${index+1}. ${s.name}`;

            const actions = document.createElement('div');
            actions.append(
                makeButton('↑',() => {
                    if (index <= 0) return;
                    [template.segments[index-1],template.segments[index]] =
                        [template.segments[index],template.segments[index-1]];
                    saveTemplates();
                    render();
                }),
                makeButton('↓',() => {
                    if (index >= template.segments.length-1) return;
                    [template.segments[index+1],template.segments[index]] =
                        [template.segments[index],template.segments[index+1]];
                    saveTemplates();
                    render();
                }),
                makeButton('Remove',() => {
                    template.segments.splice(index,1);
                    saveTemplates();
                    render();
                },'danger')
            );

            title.append(name,actions);
            card.append(title);

            const row = document.createElement('div');
            row.className = `${PREFIX}-row`;

            row.append(field('Name',makeInput(s.name,v => {
                s.name = v;
                name.textContent = `${index+1}. ${v}`;
                saveTemplates();
            })));

            row.append(field('Type',makeSelect(
                [['fixed','Fixed'],['select','Select'],['text','Text']],
                s.type,
                v => {
                    s.type = v;
                    if (v === 'select') s.options ||= [];
                    saveTemplates();
                    render();
                }
            )));

            const req = document.createElement('input');
            req.type = 'checkbox';
            req.checked = !!s.required;
            req.addEventListener('change',() => {
                s.required = req.checked;
                saveTemplates();
            });

            const reqWrap = document.createElement('label');
            reqWrap.style.display = 'flex';
            reqWrap.style.gap = '6px';
            reqWrap.style.alignItems = 'center';
            reqWrap.append(req,document.createTextNode('Required'));

            row.append(field('Validation',reqWrap));
            card.append(row);

            if (s.type === 'fixed') {
                card.append(field('Fixed value',makeInput(s.fixedValue || '',v => {
                    s.fixedValue = v;
                    saveTemplates();
                })));
            }

            if (s.type === 'text') {
                const r = document.createElement('div');
                r.className = `${PREFIX}-row`;

                r.append(
                    field('Default value',makeInput(s.defaultValue || '',v => {
                        s.defaultValue = v;
                        saveTemplates();
                    })),
                    field('Placeholder',makeInput(s.placeholder || '',v => {
                        s.placeholder = v;
                        saveTemplates();
                    }))
                );

                card.append(r);
            }

            if (s.type === 'select') {
                const ta = document.createElement('textarea');
                ta.className = `${PREFIX}-textarea`;
                ta.value = (s.options || []).map(o => `${o.value}|${o.label || o.value}`).join('\n');
                ta.placeholder = 'WIN|Windows\nMAC|macOS';

                ta.addEventListener('change',() => {
                    s.options = ta.value
                        .split(/\r?\n/)
                        .map(x => x.trim())
                        .filter(Boolean)
                        .map(line => {
                            const [v,...l] = line.split('|');
                            return { value:(v || '').trim(), label:(l.join('|') || v || '').trim() };
                        })
                        .filter(o => o.value);

                    if (!s.options.some(o => o.value === s.defaultValue)) {
                        s.defaultValue = s.options[0]?.value || '';
                    }

                    saveTemplates();
                });

                card.append(field('Options (VALUE|Label)',ta));
                card.append(field('Default value',makeInput(s.defaultValue || '',v => {
                    s.defaultValue = v;
                    saveTemplates();
                })));
            }

            const whenTitle = document.createElement('div');
            whenTitle.style.fontWeight = '600';
            whenTitle.style.marginTop = '12px';
            whenTitle.textContent = 'When';

            card.append(whenTitle,conditionEditor(template,s,index));
            body.append(card);
        });
    }

    function exportJson() {
        const payload = {
            schema:'intune-entra-naming-designer',
            version:5,
            exportedAt:new Date().toISOString(),
            templates:state.templates
        };

        const blob = new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'Intune-Entra-Naming-Templates.json';
        a.click();
        setTimeout(() => URL.revokeObjectURL(url),500);
    }

    function importJson() {
        const f = document.createElement('input');
        f.type = 'file';
        f.accept = '.json,application/json';

        f.addEventListener('change',async() => {
            const file = f.files?.[0];
            if (!file) return;

            try {
                const parsed = JSON.parse(await file.text());
                const templates = Array.isArray(parsed) ? parsed : parsed.templates;
                if (!Array.isArray(templates) || !templates.length) throw new Error('No templates found.');

                state.templates = templates;
                state.templateId = templates[0].id;
                state.values = {};
                templates.forEach(t => state.values[t.id] = valuesFor(t));
                saveTemplates();
                render();
            } catch(error) {
                alert(`Import failed: ${error.message}`);
            }
        });

        f.click();
    }

    function restoreBuiltins() {
        const ids = new Set(state.templates.map(t => t.id));
        let added = 0;

        for (const builtin of BUILTIN_TEMPLATES) {
            if (!ids.has(builtin.id)) {
                state.templates.push(clone(builtin));
                added++;
            }
        }

        if (!added) {
            alert('All built-in templates are already available. Existing templates were not overwritten.');
            return;
        }

        saveTemplates();
        render();
    }

    function renderFooter() {
        const footer = document.querySelector(`#${OVERLAY_ID} .${PREFIX}-footer`);
        if (!footer) return;
        footer.replaceChildren();

        const left = document.createElement('div');
        left.className = `${PREFIX}-muted`;
        left.textContent = `Intune & Entra Naming Designer v${VERSION}`;

        const right = document.createElement('div');
        right.className = `${PREFIX}-row`;
        right.style.margin = '0';
        right.style.justifyContent = 'flex-end';

        if (state.tab === 'builder') {
            right.append(makeButton('Apply name',() => {
                const t = currentTemplate();
                const result = buildName(t,state.values[t.id] || {});

                if (result.errors.length) {
                    alert(result.errors.join('\n'));
                    return;
                }

                if (!currentTarget?.input?.isConnected) {
                    currentTarget = findNamingTarget();
                }

                if (!currentTarget?.input) {
                    alert('The target Name field is no longer available.');
                    return;
                }

                setReactValue(currentTarget.input,result.name);
                closeDesigner();
            },'primary'));
        }

        right.append(makeButton('Close',closeDesigner));
        footer.append(left,right);
    }

    function openDesigner() {
        if (document.getElementById(OVERLAY_ID)) return;
        ensureStyle();

        const templates = loadTemplates();
        const surface = currentTarget?.surface || detectSurface();
        const templateId = preferredTemplateId(templates,surface);

        state = {
            templates,
            templateId,
            surface,
            tab:'builder',
            values:{}
        };

        templates.forEach(t => state.values[t.id] = valuesFor(t));

        const overlay = document.createElement('div');
        overlay.id = OVERLAY_ID;

        const panel = document.createElement('div');
        panel.className = `${PREFIX}-panel`;

        const header = document.createElement('div');
        header.className = `${PREFIX}-header`;

        const title = document.createElement('div');
        title.textContent = 'Intune & Entra Naming Designer';

        const x = document.createElement('button');
        x.type = 'button';
        x.className = `${PREFIX}-close`;
        x.textContent = '×';
        x.onclick = closeDesigner;

        header.append(title,x);

        const tabs = document.createElement('div');
        tabs.className = `${PREFIX}-tabs`;

        [['builder','Build name'],['designer','Template designer']].forEach(([tab,label]) => {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = `${PREFIX}-tab`;
            b.dataset.tab = tab;
            b.textContent = label;
            b.onclick = () => {
                state.tab = tab;
                render();
            };
            tabs.append(b);
        });

        const body = document.createElement('div');
        body.className = `${PREFIX}-body`;

        const footer = document.createElement('div');
        footer.className = `${PREFIX}-footer`;

        panel.append(header,tabs,body,footer);
        overlay.append(panel);
        document.body.append(overlay);

        overlay.addEventListener('mousedown',e => {
            if (e.target === overlay) closeDesigner();
        });

        render();
    }

    function closeDesigner() {
        document.getElementById(OVERLAY_ID)?.remove();
        state = null;
    }

    function scan() {
        const target = findNamingTarget();
        if (!target) return;

        lastCandidate = target;
        currentTarget = target;
        injectButton(target);
    }

    function start() {
        console.info('[Naming Designer] Userscript loaded.', {
            version:VERSION,
            frameName:window.name || '',
            url:location.href
        });

        const observer = new MutationObserver(scan);
        observer.observe(document.documentElement,{subtree:true,childList:true});

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded',scan,{once:true});
        } else {
            scan();
        }

        setInterval(scan,1200);
    }

    start();
})();
