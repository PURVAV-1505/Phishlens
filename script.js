// =====================================================
// PHISHLENS JAVASCRIPT
// =====================================================


// -----------------------------------------------------
// CONFIGURATION
// -----------------------------------------------------

const SUSPICIOUS_TLDS = [
  'xyz',
  'top',
  'tk',
  'buzz',
  'click',
  'cfd',
  'icu',
  'cam',
  'work',
  'fit',
  'rest',
  'gq',
  'ga',
  'ml',
  'cf',
  'sbs',
  'quest',
  'loan',
  'racing'
];


const TARGETED_BRANDS = [
  'google',
  'apple',
  'microsoft',
  'paypal',
  'netflix',
  'amazon',
  'facebook',
  'instagram',
  'sbi',
  'hdfc',
  'icici',
  'chase',
  'wellsfargo',
  'binance',
  'coinbase',
  'metamask',
  'github',
  'whatsapp',
  'telegram'
];


const URGENCY_KEYWORDS = [
  'verify',
  'verification',
  'update',
  'kyc',
  'pan',
  'blocked',
  'suspended',
  'login',
  'signin',
  'auth',
  'security',
  'alert',
  'confirm',
  'wallet',
  'recover',
  'refund',
  'lottery',
  'winner',
  'reward',
  'gift',
  'bonus'
];


const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly'
];


// -----------------------------------------------------
// GLOBAL VARIABLES
// -----------------------------------------------------

let currentInputMode = 'url';

let currentUploadedImageBase64 = null;

let currentUploadedImageMime = null;

let currentAnalysisData = null;


// -----------------------------------------------------
// INPUT MODE SWITCHING
// -----------------------------------------------------

function switchInputMode(mode) {

  currentInputMode = mode;

  const tabUrl =
    document.getElementById('tabBtnUrl');

  const tabFile =
    document.getElementById('tabBtnFile');

  const urlContainer =
    document.getElementById('urlInputContainer');

  const fileContainer =
    document.getElementById('fileInputContainer');


  if (mode === 'url') {

    tabUrl.className =
      'flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold transition-all bg-emerald-500 text-slate-950 shadow-md shadow-emerald-500/20';

    tabFile.className =
      'flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold text-slate-400 hover:text-slate-200 transition-all';

    urlContainer.classList.remove('hidden');

    fileContainer.classList.add('hidden');

  }

  else {

    tabFile.className =
      'flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold transition-all bg-emerald-500 text-slate-950 shadow-md shadow-emerald-500/20';

    tabUrl.className =
      'flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold text-slate-400 hover:text-slate-200 transition-all';

    fileContainer.classList.remove('hidden');

    urlContainer.classList.add('hidden');

  }
}


// -----------------------------------------------------
// FILE DRAG & DROP
// -----------------------------------------------------

const dropZone =
  document.getElementById('dropZone');


if (dropZone) {

  ['dragenter', 'dragover'].forEach(eventName => {

    dropZone.addEventListener(
      eventName,
      e => {

        e.preventDefault();

        dropZone.classList.add(
          'border-emerald-400',
          'bg-slate-900/90'
        );

      }
    );

  });


  ['dragleave', 'drop'].forEach(eventName => {

    dropZone.addEventListener(
      eventName,
      e => {

        e.preventDefault();

        dropZone.classList.remove(
          'border-emerald-400',
          'bg-slate-900/90'
        );

      }
    );

  });


  dropZone.addEventListener('drop', e => {

    const files =
      e.dataTransfer.files;

    if (files && files.length > 0) {

      processSelectedFile(files[0]);

    }

  });

}


// -----------------------------------------------------
// FILE UPLOAD
// -----------------------------------------------------

function handleFileUpload(event) {

  const file =
    event.target.files?.[0];

  if (file) {

    processSelectedFile(file);

  }

}


function processSelectedFile(file) {

  const fileName =
    file.name;

  const fileSizeKb =
    Math.round(file.size / 1024);

  const isImage =
    file.type.startsWith('image/');


  if (isImage) {

    const reader =
      new FileReader();


    reader.onload = e => {

      const fullDataUrl =
        e.target.result;

      const base64Data =
        fullDataUrl.split(',')[1];


      currentUploadedImageBase64 =
        base64Data;

      currentUploadedImageMime =
        file.type;


      analyzeMediaThreat({

        fileName,

        fileSizeKb,

        isImage: true,

        mimeType: file.type,

        hasDoubleExtension:
          checkDoubleExtension(fileName),

        isApk:
          fileName
            .toLowerCase()
            .endsWith('.apk')

      });

    };


    reader.readAsDataURL(file);

  }

  else {

    currentUploadedImageBase64 = null;

    currentUploadedImageMime = null;


    analyzeMediaThreat({

      fileName,

      fileSizeKb,

      isImage: false,

      mimeType:
        file.type ||
        'application/octet-stream',

      hasDoubleExtension:
        checkDoubleExtension(fileName),

      isApk:
        fileName
          .toLowerCase()
          .endsWith('.apk')

    });

  }

}


// -----------------------------------------------------
// DOUBLE EXTENSION DETECTOR
// -----------------------------------------------------

function checkDoubleExtension(name) {

  const lower =
    name.toLowerCase();

  return /(\.(pdf|docx?|xlsx?|jpg|png|mp4)\.(apk|exe|scr|vbs|bat|msi))$/i
    .test(lower);

}


// -----------------------------------------------------
// FILE SCAM SIMULATIONS
// -----------------------------------------------------

function simulateFileScam(type) {

  currentUploadedImageBase64 = null;

  currentUploadedImageMime = null;


  if (type === 'wedding_apk') {

    analyzeMediaThreat({

      fileName:
        'Wedding_Invitation_Card_Rohan&Neha.pdf.apk',

      fileSizeKb: 4320,

      isImage: false,

      mimeType:
        'application/vnd.android.package-archive',

      hasDoubleExtension: true,

      isApk: true,

      simulatedContext:
        'WhatsApp message: "Bhai shaadi me zaroor aana, card bhej raha hu open karke dekh lo!"'

    });

  }


  else if (type === 'electricity_bill') {

    analyzeMediaThreat({

      fileName:
        'Electricity_Power_Disconnection_Notice.jpg',

      fileSizeKb: 480,

      isImage: true,

      mimeType: 'image/jpeg',

      hasDoubleExtension: false,

      isApk: false,

      simulatedContext:
        'WhatsApp image alert: "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Immediately contact Electricity Officer."'

    });

  }


  else if (type === 'fake_qr') {

    analyzeMediaThreat({

      fileName:
        'Instant_Cashback_Refund_QR.png',

      fileSizeKb: 310,

      isImage: true,

      mimeType: 'image/png',

      hasDoubleExtension: false,

      isApk: false,

      simulatedContext:
        'WhatsApp QR image: "Scan this QR code to receive Rs 25,000 lottery refund directly into your UPI account."'

    });

  }


  else if (type === 'echallan_pdf') {

    analyzeMediaThreat({

      fileName:
        'Traffic_EChallan_Court_Notice.pdf.apk',

      fileSizeKb: 5210,

      isImage: false,

      mimeType:
        'application/vnd.android.package-archive',

      hasDoubleExtension: true,

      isApk: true,

      simulatedContext:
        'SMS alert: "Your vehicle has 3 pending court traffic fines. Download copy of challan to avoid warrant."'

    });

  }

}


// -----------------------------------------------------
// MEDIA THREAT ANALYSIS
// -----------------------------------------------------

function analyzeMediaThreat(fileMeta) {

  let score = 100;

  const flags = [];


  if (fileMeta.isApk) {

    score -= 60;

    flags.push({

      type: 'danger',

      title:
        'Android Executable (.APK Package) Detected',

      desc:
        'This file is an Android application package, NOT a document or photo.'

    });

  }


  if (fileMeta.hasDoubleExtension) {

    score -= 40;

    flags.push({

      type: 'danger',

      title:
        'Deceptive Double Extension Disguise',

      desc:
        `The file name "${fileMeta.fileName}" has a fake extension followed by a dangerous executable.`

    });

  }


  if (fileMeta.simulatedContext) {

    score -= 20;

    flags.push({

      type: 'warning',

      title:
        'Extreme Panic / Urgency Social Engineering',

      desc:
        'The message uses urgency, fear, authority or reward-based manipulation.'

    });

  }


  score =
    Math.max(
      5,
      Math.min(100, score)
    );


  renderResults({

    url: fileMeta.fileName,

    score,

    protocol:
      fileMeta.isImage
        ? 'IMAGE-MEDIA'
        : 'APPLICATION',

    subdomain:
      fileMeta.isApk
        ? 'SUSPECT-PACKAGE'
        : 'VERIFIED-MIME',

    rootDomain:
      fileMeta.fileName,

    fullPath:
      `[Size: ${fileMeta.fileSizeKb} KB] [Type: ${fileMeta.mimeType}]`,

    tld:
      fileMeta.isApk
        ? 'apk'
        : 'media',

    punycodeDomain:
      fileMeta.fileName,

    hasHomoglyph:
      fileMeta.hasDoubleExtension,

    flags

  });


  setTimeout(() => {

    triggerAIAnalysis(
      'forensic',
      fileMeta
    );

  }, 300);

}


// -----------------------------------------------------
// SAMPLE URL
// -----------------------------------------------------

function setSample(url) {

  document.getElementById(
    'urlInput'
  ).value = url;


  document.getElementById(
    'clearBtn'
  ).classList.remove('hidden');


  analyzeUrl();

}


// -----------------------------------------------------
// CLEAR INPUT
// -----------------------------------------------------

function clearInput() {

  document.getElementById(
    'urlInput'
  ).value = '';


  document.getElementById(
    'clearBtn'
  ).classList.add('hidden');


  document.getElementById(
    'resultsWrapper'
  ).classList.add('hidden');


  document.getElementById(
    'urlInput'
  ).focus();

}


// -----------------------------------------------------
// INPUT EVENT
// -----------------------------------------------------

const urlInput =
  document.getElementById('urlInput');


if (urlInput) {

  urlInput.addEventListener(
    'input',
    e => {

      const btn =
        document.getElementById(
          'clearBtn'
        );


      if (
        e.target.value.trim().length > 0
      ) {

        btn.classList.remove(
          'hidden'
        );

      }

      else {

        btn.classList.add(
          'hidden'
        );

      }

    }
  );

}


// -----------------------------------------------------
// URL HELPERS
// -----------------------------------------------------

function containsNonAscii(str) {

  return /[^\u0000-\u007F]/.test(str);

}


function isRawIP(hostname) {

  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    .test(hostname);

}


// -----------------------------------------------------
// URL ANALYZER
// -----------------------------------------------------

function analyzeUrl() {

  let rawInput =
    document.getElementById(
      'urlInput'
    ).value.trim();


  if (!rawInput) return;


  const urlRegex =
    /(https?:\/\/[^\s]+)/i;


  const matched =
    rawInput.match(urlRegex);


  let targetUrl =
    matched
      ? matched[0]
      : rawInput;


  if (
    !/^https?:\/\//i.test(
      targetUrl
    )
  ) {

    targetUrl =
      'https://' + targetUrl;

  }


  let parsed;


  try {

    parsed =
      new URL(targetUrl);

  }

  catch (err) {

    showToast(
      'Invalid URL syntax.'
    );

    return;

  }


  let score = 100;

  const flags = [];


  const protocol =
    parsed.protocol.replace(':', '');

  const hostname =
    parsed.hostname.toLowerCase();

  const pathname =
    parsed.pathname;

  const search =
    parsed.search;

  const fullPath =
    pathname + search;


  // HTTP

  if (protocol === 'http') {

    score -= 25;

    flags.push({

      type: 'danger',

      title:
        'Unencrypted Connection (HTTP)',

      desc:
        'The connection does not use TLS encryption.'

    });

  }


  // Unicode

  const hasHomoglyph =
    containsNonAscii(hostname);


  let punycodeDomain =
    hostname;


  if (hasHomoglyph) {

    score -= 45;

    const chars =
      [...new Set(
        hostname.match(
          /[^\u0000-\u007F]/g
        ) || []
      )].join(' ');


    flags.push({

      type: 'danger',

      title:
        'Hidden Unicode / Cyrillic Character Detected',

      desc:
        `The hostname contains lookalike characters (${chars}).`

    });

  }


  // Raw IP

  if (isRawIP(hostname)) {

    score -= 30;

    flags.push({

      type: 'danger',

      title:
        'Raw IP Address Host',

      desc:
        'The URL uses a raw IP address instead of a registered domain.'

    });

  }


  // Shortener

  const isShortener =
    URL_SHORTENERS.includes(hostname);


  if (isShortener) {

    score -= 15;

    flags.push({

      type: 'warning',

      title:
        'URL Shortener In Use',

      desc:
        'The shortened URL hides its final destination.'

    });

  }


  // Domain decomposition

  const hostParts =
    hostname.split('.');


  let rootDomain =
    hostname;

  let subdomain = '';

  let tld = '';


  if (
    !isRawIP(hostname) &&
    hostParts.length >= 2
  ) {

    const isDualTld =
      hostParts.length > 2 &&
      [
        'co',
        'com',
        'org',
        'edu',
        'gov',
        'net'
      ].includes(
        hostParts[
          hostParts.length - 2
        ]
      );


    if (
      isDualTld &&
      hostParts.length >= 3
    ) {

      tld =
        hostParts
          .slice(-2)
          .join('.');


      rootDomain =
        hostParts
          .slice(-3)
          .join('.');


      subdomain =
        hostParts
          .slice(0, -3)
          .join('.');

    }

    else {

      tld =
        hostParts[
          hostParts.length - 1
        ];


      rootDomain =
        hostParts
          .slice(-2)
          .join('.');


      subdomain =
        hostParts
          .slice(0, -2)
          .join('.');

    }

  }


  // Suspicious TLD

  if (
    SUSPICIOUS_TLDS.includes(tld)
  ) {

    score -= 20;

    flags.push({

      type: 'warning',

      title:
        `High-Risk Top Level Domain (.${tld})`,

      desc:
        `The .${tld} extension deserves additional scrutiny.`

    });

  }


  // Deep subdomains

  if (hostParts.length >= 4) {

    score -= 15;

    flags.push({

      type: 'warning',

      title:
        'Excessive Subdomain Nesting',

      desc:
        `The URL contains ${hostParts.length - 1} subdomains.`

    });

  }


  // Brand impersonation

  if (subdomain) {

    TARGETED_BRANDS.forEach(
      brand => {

        if (
          subdomain.includes(brand) &&
          !rootDomain.includes(brand)
        ) {

          score -= 35;

          flags.push({

            type: 'danger',

            title:
              `Brand Impersonation Trick ('${brand}')`,

            desc:
              `The brand appears in the subdomain while the actual root domain is ${rootDomain}.`

          });

        }

      }
    );

  }


  // Urgency

  const combinedText =
    (
      hostname +
      fullPath
    ).toLowerCase();


  const detectedKeywords =
    URGENCY_KEYWORDS.filter(
      word =>
        combinedText.includes(word)
    );


  if (
    detectedKeywords.length > 0
  ) {

    const penalty =
      Math.min(
        25,
        detectedKeywords.length * 8
      );


    score -= penalty;


    flags.push({

      type: 'warning',

      title:
        'Social Engineering Urgency Triggers',

      desc:
        `Detected trigger words: ${detectedKeywords.slice(0, 4).join(', ')}`

    });

  }


  score =
    Math.max(
      5,
      Math.min(100, score)
    );


  renderResults({

    url: targetUrl,

    score,

    protocol,

    subdomain,

    rootDomain,

    fullPath,

    tld,

    punycodeDomain,

    hasHomoglyph,

    flags

  });

}


// -----------------------------------------------------
// RENDER RESULTS
// -----------------------------------------------------

function renderResults(data) {

  const resultsWrapper =
    document.getElementById(
      'resultsWrapper'
    );


  resultsWrapper.classList.remove(
    'hidden'
  );


  const scoreText =
    document.getElementById(
      'scoreText'
    );


  const scoreMeterPath =
    document.getElementById(
      'scoreMeterPath'
    );


  const scoreCard =
    document.getElementById(
      'scoreCard'
    );


  const riskBadge =
    document.getElementById(
      'riskBadge'
    );


  const riskTitle =
    document.getElementById(
      'riskTitle'
    );


  const riskSubtitle =
    document.getElementById(
      'riskSubtitle'
    );


  const recActionText =
    document.getElementById(
      'recActionText'
    );


  scoreText.innerText =
    data.score;


  scoreMeterPath.setAttribute(
    'stroke-dasharray',
    `${data.score}, 100`
  );


  // SAFE

  if (data.score >= 80) {

    scoreMeterPath.setAttribute(
      'stroke',
      '#10b981'
    );


    scoreText.className =
      'text-2xl font-black font-mono-code leading-none text-emerald-400';


    riskBadge.innerText =
      'Safe / Low Threat';


    riskTitle.innerText =
      'No Critical Deception Patterns Found';


    riskSubtitle.innerText =
      'The URL structure aligns with standard conventions.';


    recActionText.innerText =
      'Proceed Normally';

  }


  // SUSPICIOUS

  else if (data.score >= 50) {

    scoreMeterPath.setAttribute(
      'stroke',
      '#f59e0b'
    );


    scoreText.className =
      'text-2xl font-black font-mono-code leading-none text-amber-400';


    riskBadge.innerText =
      'Suspicious / Proceed with Caution';


    riskTitle.innerText =
      'Potentially Misleading Elements Found';


    riskSubtitle.innerText =
      'Inspect the root domain carefully.';


    recActionText.innerText =
      'Verify Before Submitting Data';

  }


  // HIGH RISK

  else {

    scoreMeterPath.setAttribute(
      'stroke',
      '#ef4444'
    );


    scoreText.className =
      'text-2xl font-black font-mono-code leading-none text-rose-500';


    riskBadge.innerText =
      'High Risk / Malicious Phish';


    riskTitle.innerText =
      'Dangerous Deception Detected!';


    riskSubtitle.innerText =
      'Severe phishing indicators were detected.';


    recActionText.innerText =
      'DO NOT CLICK / Close Tab';

  }


  // URL ANATOMY

  document.getElementById(
    'pillProtocol'
  ).innerText =
    data.protocol + ':';


  document.getElementById(
    'pillSubdomain'
  ).innerText =
    data.subdomain
      ? data.subdomain + '.'
      : '';


  document.getElementById(
    'pillRootDomain'
  ).innerText =
    data.rootDomain;


  document.getElementById(
    'pillPath'
  ).innerText =
    data.fullPath &&
    data.fullPath !== '/'
      ? data.fullPath
      : '/';


  document.getElementById(
    'detailRootDomain'
  ).innerText =
    data.rootDomain;


  document.getElementById(
    'detailPunycode'
  ).innerText =
    data.hasHomoglyph
      ? `xn--${encodeURIComponent(data.rootDomain)}`
      : 'Standard ASCII';


  document.getElementById(
    'detailEncryption'
  ).innerText =
    data.protocol.toUpperCase();


  // FLAGS

  const riskList =
    document.getElementById(
      'riskList'
    );


  const flagCounter =
    document.getElementById(
      'flagCounter'
    );


  riskList.innerHTML = '';


  flagCounter.innerText =
    `${data.flags.length} Indicator${data.flags.length === 1 ? '' : 's'}`;


  if (data.flags.length === 0) {

    riskList.innerHTML = `

      <div class="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-xs flex items-center gap-3">

        <span class="text-xl">
          🛡️
        </span>

        <div>

          <p class="font-bold text-sm">
            All Heuristic Checks Passed
          </p>

          <p class="text-slate-400 mt-0.5">
            No major structural risk indicators were detected.
          </p>

        </div>

      </div>

    `;

  }

  else {

    data.flags.forEach(flag => {

      const isDanger =
        flag.type === 'danger';


      const cardBorder =
        isDanger
          ? 'border-rose-500/30 bg-rose-950/20'
          : 'border-amber-500/30 bg-amber-950/20';


      const titleColor =
        isDanger
          ? 'text-rose-400'
          : 'text-amber-400';


      const icon =
        isDanger
          ? '🚨'
          : '⚠️';


      const item =
        document.createElement('div');


      item.className =
        `p-3.5 rounded-xl border ${cardBorder} flex gap-3 text-xs leading-relaxed`;


      item.innerHTML = `

        <span class="text-base">
          ${icon}
        </span>

        <div>

          <p class="font-bold text-sm ${titleColor}">
            ${flag.title}
          </p>

          <p class="text-slate-300 mt-1">
            ${flag.desc}
          </p>

        </div>

      `;


      riskList.appendChild(item);

    });

  }


  resultsWrapper.scrollIntoView({
    behavior: 'smooth',
    block: 'nearest'
  });


  resetAICard();

}


// -----------------------------------------------------
// RESET AI
// -----------------------------------------------------

function resetAICard() {

  const placeholder =
    document.getElementById(
      'aiPlaceholder'
    );


  const loading =
    document.getElementById(
      'aiLoading'
    );


  const resultText =
    document.getElementById(
      'aiResultText'
    );


  const sources =
    document.getElementById(
      'aiSources'
    );


  placeholder.classList.remove(
    'hidden'
  );


  loading.classList.add(
    'hidden'
  );


  resultText.classList.add(
    'hidden'
  );


  sources.classList.add(
    'hidden'
  );


  resultText.innerHTML = '';

}


// -----------------------------------------------------
// COPY REPORT
// -----------------------------------------------------

function copyAuditReport() {

  const url =
    document.getElementById(
      'urlInput'
    ).value.trim();


  const score =
    document.getElementById(
      'scoreText'
    ).innerText;


  const rootDomain =
    document.getElementById(
      'detailRootDomain'
    ).innerText;


  const flagsCount =
    document.getElementById(
      'flagCounter'
    ).innerText;


  const report = `

[PhishLens Security Audit Report]

Analyzed URL:
${url}

Safety Score:
${score}/100

Identified Root Host:
${rootDomain}

Flags Triggered:
${flagsCount}

Timestamp:
${new Date().toUTCString()}

Verified client-side via PhishLens.

`;


  try {

    const textarea =
      document.createElement(
        'textarea'
      );


    textarea.value =
      report;


    textarea.setAttribute(
      'readonly',
      ''
    );


    textarea.style.position =
      'fixed';

    textarea.style.left =
      '-9999px';


    document.body.appendChild(
      textarea
    );


    textarea.focus();

    textarea.select();


    const successful =
      document.execCommand(
        'copy'
      );


    document.body.removeChild(
      textarea
    );


    if (successful) {

      showToast(
        'Audit summary copied to clipboard!'
      );

    }

    else {

      showToast(
        'Unable to copy automatically.'
      );

    }

  }

  catch (err) {

    showToast(
      'Unable to copy summary.'
    );

  }

}


// -----------------------------------------------------
// TOAST
// -----------------------------------------------------

function showToast(msg) {

  const toast =
    document.getElementById(
      'toast'
    );


  const toastMsg =
    document.getElementById(
      'toastMsg'
    );


  toastMsg.innerText =
    msg;


  toast.classList.remove(
    'translate-y-20',
    'opacity-0'
  );


  setTimeout(() => {

    toast.classList.add(
      'translate-y-20',
      'opacity-0'
    );

  }, 2500);

}