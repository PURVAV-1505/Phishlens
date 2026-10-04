import base64
import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env')

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '').strip()
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-3.8-flash').strip()

app = FastAPI(title='PhishLens API', version='2.0.0')

origins = [x.strip() for x in os.getenv('CORS_ORIGINS', 'http://127.0.0.1:8000,http://localhost:8000').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

app.mount('/css', StaticFiles(directory=ROOT / 'css'), name='css')
app.mount('/js', StaticFiles(directory=ROOT / 'js'), name='js')

class Media(BaseModel):
    fileName: str | None = None
    mimeType: str | None = None
    sizeKb: int | None = None
    isApk: bool = False
    hasDoubleExtension: bool = False
    simulatedContext: str | None = None
    qrValue: str | None = None
    dataBase64: str | None = None

class Analysis(BaseModel):
    score: int | None = None
    confidence: int | None = None
    rootDomain: str | None = None
    protocol: str | None = None
    flags: str | None = None

class AIRequest(BaseModel):
    mode: str = Field(default='forensic')
    target: str
    analysis: Analysis | None = None
    media: Media | None = None

@app.get('/')
async def index():
    return FileResponse(ROOT / 'index.html')

@app.get('/api/health')
async def health():
    return {'status': 'ok', 'gemini_configured': bool(GEMINI_API_KEY), 'model': GEMINI_MODEL}

@app.post('/api/ai/analyze')
async def ai_analyze(req: AIRequest):
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail='GEMINI_API_KEY is not configured on the backend.')

    mode = req.mode if req.mode in {'forensic', 'simple', 'report'} else 'forensic'
    a = req.analysis or Analysis()
    flags = a.flags or 'No structural flags'

    if req.media:
        system = (
            'You are a cybersecurity and digital-safety analyst. Analyze user-supplied media or file metadata conservatively. '
            'Do not claim that a file is malicious solely from its filename or extension. Clearly separate observed evidence from inference. '
            'Never instruct the user to install, execute, or open a suspicious file.'
        )
        user = (
            f'Analyze this uploaded item. File: {req.media.fileName}. MIME: {req.media.mimeType}. Size: {req.media.sizeKb} KB. '
            f'APK: {req.media.isApk}. Double extension: {req.media.hasDoubleExtension}. QR payload: {req.media.qrValue or "not decoded locally"}. '
            f'Context: {req.media.simulatedContext or "none"}. Heuristic score: {a.score}/100. Flags: {flags}. '
        )
        if mode == 'simple':
            user += 'Explain the result in simple Hinglish/English, with clear do/don’t actions. Keep under 180 words.'
        elif mode == 'report':
            user += 'Draft a concise incident notice with evidence, uncertainty, immediate containment, and reporting fields. Do not invent facts.'
        else:
            user += 'Provide threat classification, observed evidence, social-engineering cues, technical limitations, and immediate safety steps. Keep under 240 words.'
    else:
        system = (
            'You are a threat-intelligence analyst. Evaluate URL evidence conservatively. A heuristic score is not proof of safety or compromise. '
            'Do not invent reputation, ownership, malware, or campaign evidence. If web search is enabled, cite only evidence actually found.'
        )
        user = (
            f'Analyze URL: {req.target}\nRoot domain: {a.rootDomain}\nProtocol: {a.protocol}\n'
            f'PhishLens structural score: {a.score}/100\nHeuristic confidence: {a.confidence}%\nFlags: {flags}\n'
        )
        if mode == 'simple':
            user += 'Explain in simple Hinglish/English what the signals mean and how to verify the site safely. Keep under 180 words.'
        elif mode == 'report':
            user += 'Create a concise security incident notice with target, evidence, uncertainty, and recommended containment. Do not invent facts.'
        else:
            user += 'Provide threat classification, psychological bait, technical red flags, and immediate containment steps. Keep under 250 words.'

    parts = [{'text': user}]
    if req.media and req.media.dataBase64 and req.media.mimeType in {'image/png','image/jpeg','image/webp','application/pdf'}:
        try:
            base64.b64decode(req.media.dataBase64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail='Invalid media encoding.')
        parts.append({'inline_data': {'mime_type': req.media.mimeType, 'data': req.media.dataBase64}})

    payload = {
        'contents': [{'role': 'user', 'parts': parts}],
        'system_instruction': {'parts': [{'text': system}]},
    }
    if not req.media and mode == 'forensic':
        payload['tools'] = [{'google_search': {}}]

    url = f'https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent'
    headers = {'x-goog-api-key': GEMINI_API_KEY, 'Content-Type': 'application/json'}

    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f'Gemini connection failed: {exc}')

    if response.status_code >= 400:
        detail = response.text[:800]
        raise HTTPException(status_code=502, detail=f'Gemini API error: {detail}')

    data = response.json()
    candidates = data.get('candidates') or []
    text_parts = []
    if candidates:
        for part in (candidates[0].get('content') or {}).get('parts') or []:
            if part.get('text'):
                text_parts.append(part['text'])
    result_text = '\n'.join(text_parts).strip()
    if not result_text:
        raise HTTPException(status_code=502, detail='Gemini returned no text.')

    sources = []
    candidate = candidates[0] if candidates else {}
    grounding = candidate.get('groundingMetadata') or {}
    for item in grounding.get('groundingAttributions') or []:
        web = item.get('web') or {}
        if web.get('uri'):
            sources.append({'uri': web['uri'], 'title': web.get('title') or web['uri']})

    return {'text': result_text, 'sources': sources[:4], 'model': GEMINI_MODEL}


def _is_public_hostname(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
        addresses = {item[4][0] for item in infos}
        return bool(addresses) and all(_is_public_hostname(addr) for addr in addresses)
    except OSError:
        return False

@app.post('/api/resolve-url')
async def resolve_url(body: dict):
    raw = str(body.get('url') or '').strip()
    if not raw:
        raise HTTPException(status_code=400, detail='URL is required.')
    parsed = urlparse(raw if '://' in raw else f'https://{raw}')
    if parsed.scheme not in {'http','https'} or not parsed.hostname:
        raise HTTPException(status_code=400, detail='Only HTTP/HTTPS URLs are allowed.')
    if not _is_public_hostname(parsed.hostname):
        raise HTTPException(status_code=400, detail='Private, loopback, or non-public destinations are not resolved.')
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, max_redirects=5) as client:
            response = await client.head(raw, headers={'User-Agent':'PhishLens-Safe-Resolver/1.0'})
            if response.status_code >= 400:
                response = await client.get(raw, headers={'User-Agent':'PhishLens-Safe-Resolver/1.0'}, follow_redirects=True)
        final = str(response.url)
        final_host = urlparse(final).hostname
        if not final_host or not _is_public_hostname(final_host):
            raise HTTPException(status_code=400, detail='Redirected to a non-public destination; resolution stopped.')
        return {'finalUrl': final, 'status': response.status_code, 'redirected': final != raw}
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f'Unable to resolve destination: {exc}')
