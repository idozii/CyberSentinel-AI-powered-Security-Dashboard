"""Private loopback-only Auth0 owner portal for the PostgreSQL staging pilot.

No public listener, browser access token, refresh token, email collection, or
telemetry migration. Run single worker; sessions are intentionally in-memory.
"""
from __future__ import annotations

import html
import ipaddress
import secrets
import uuid
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from hosted_api.postgres import HostedError, HostedStore, identity_id
from hosted_api.monitoring import MonitoringStore
from hosted_api.settings import HostedSettings
from hosted_api.web_auth import (Auth0CodeExchange, COOKIE, FLOW_COOKIE, MemorySessions,
                                  WebLoginError, WebSettings)
from owner_api.dns_verify import lookup_txt


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, content: str, *, csrf: str | None = None) -> HTMLResponse:
    # Only developer-authored markup is accepted in content; user/database fields
    # must always be escaped with esc before adding to the HTML body.
    result = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} - CyberSentinel</title>
<style>body{{font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;background:#111827;color:#f9fafb}}a{{color:#93c5fd}}input,button{{font:inherit;padding:8px;margin:4px}}input{{max-width:95%}}button{{background:#2563eb;color:white;border:0;border-radius:5px;cursor:pointer}}main{{background:#1f2937;border-radius:12px;padding:24px}}.box{{border:1px solid #4b5563;padding:12px;margin:14px 0;border-radius:8px}}small{{color:#d1d5db}}code{{overflow-wrap:anywhere}}form{{margin:12px 0}}</style></head>
<body><h1>CyberSentinel <small>private staging</small></h1><main><h2>{esc(title)}</h2>{content}</main>
<footer><p><small>Only localhost access. Not a public SaaS dashboard or live hosted detector.</small></p></footer></body></html>'''
    return HTMLResponse(result)


def create_web_app(settings: WebSettings | None = None, exchanger=None,
                   store=None, sessions=None, dns_lookup=None, monitoring=None) -> FastAPI:
    cfg = settings or WebSettings.from_env()
    exchange = exchanger or Auth0CodeExchange(cfg)
    pg = store or HostedStore(cfg.hosted.runtime_dsn)
    ops = monitoring or MonitoringStore(cfg.hosted.runtime_dsn)
    state = sessions or MemorySessions()
    dns = dns_lookup or lookup_txt
    api = FastAPI(title='CyberSentinel Private Browser Pilot',
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1','localhost','testserver'])

    @api.middleware('http')
    async def loopback_only(req: Request, call_next):
        host = req.client.host if req.client else ''
        try:
            permitted = ipaddress.ip_address(host).is_loopback
        except ValueError:
            permitted = host == 'testclient'
        if not permitted:
            return JSONResponse({'detail': 'Private staging only'}, status_code=403)
        response = await call_next(req)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @api.exception_handler(HostedError)
    async def err_hosted(_req, error: HostedError):
        return page('Request not completed', '<p>'+esc(str(error))+'</p><p><a href="/">Return to portal</a></p>') if error.code < 500 else JSONResponse({'detail':'Storage temporarily unavailable'},status_code=503)

    def current(req: Request):
        item = state.get(req.cookies.get(COOKIE))
        if not item:
            raise HTTPException(status_code=401, detail='Login required')
        return item

    async def post_fields(req: Request) -> dict[str, str]:
        if req.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/x-www-form-urlencoded':
            raise HTTPException(415, detail='Only form submissions accepted')
        if (raw_len := req.headers.get('content-length')) and (not raw_len.isdecimal() or int(raw_len) > 2048):
            raise HTTPException(413, detail='Form too large')
        body = await req.body()
        if len(body) > 2048:
            raise HTTPException(413, detail='Form too large')
        try:
            vals = parse_qs(body.decode('utf-8'), strict_parsing=True, max_num_fields=8, keep_blank_values=True)
        except (UnicodeError, ValueError) as exc:
            raise HTTPException(422, detail='Invalid form') from exc
        if any(len(v) != 1 for v in vals.values()):
            raise HTTPException(422, detail='Ambiguous form')
        return {k: v[0] for k, v in vals.items()}

    def check_csrf(fields: dict, sess):
        if not secrets.compare_digest(str(fields.get('_csrf', '')), sess.csrf):
            raise HTTPException(403, detail='Invalid CSRF token')

    @api.get('/')
    def home(req: Request):
        if not state.get(req.cookies.get(COOKIE)):
            return page('Sign in', '<p>Connect your Auth0 account to manage your DNS-verified domains.</p><p><a href="/auth/login">Sign in with Auth0</a></p>')
        return RedirectResponse('/domains', status_code=303)

    @api.get('/auth/login')
    def login():
        try:
            random_state, browser_binding, pending = state.begin()
        except WebLoginError as exc:
            raise HTTPException(429, detail=str(exc)) from exc
        response = RedirectResponse(exchange.authorize_url(random_state, pending), status_code=302)
        response.set_cookie(FLOW_COOKIE, browser_binding, max_age=300, httponly=True,
                            secure=False, samesite='lax', path='/auth')
        return response

    @api.get('/auth/callback')
    def callback(req: Request, code: str = '', error: str = ''):
        # Auth0 returns the OAuth parameter named 'state'. FastAPI parameter alias
        # is avoided here so tests and callback query parsing stay explicit.
        state_value = req.query_params.get('state', '')
        if (len(req.query_params) > 8 or len(req.query_params.getlist('state')) != 1
                or len(req.query_params.getlist('code')) > 1):
            raise HTTPException(422, detail='Invalid callback')
        try:
            pending = state.consume(state_value, req.cookies.get(FLOW_COOKIE))
            if error:
                raise WebLoginError('Auth0 declined login')
            subject = exchange.exchange(code, pending)
            pg.ensure_identity(subject)
            sid = state.issue(subject)
        except WebLoginError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
        response = RedirectResponse('/domains', status_code=303)
        response.delete_cookie(FLOW_COOKIE, path='/auth')
        response.set_cookie(COOKIE, sid, max_age=1800, httponly=True,
                            secure=False, samesite='lax', path='/')
        return response

    @api.get('/domains')
    def domains(req: Request):
        sess = current(req)
        domains = pg.list_domains(sess.subject)
        lines = ['<p>Owner ref: <code>'+esc(str(identity_id(sess.subject))[:12])+'</code></p>',
                 '<h3>Your domains</h3>']
        if not domains:
            lines.append('<p>No domains yet. Add a domain you control.</p>')
        for item in domains:
            lines.append('<div class="box"><strong>'+esc(item['domain'])+'</strong> - '
                         + ('Verified' if item['verified'] else 'Awaiting DNS proof'))
            if item['verified']:
                lines.append('<p><a href="/domains/'+esc(item['id'])+'/monitor">Manage monitoring</a></p>')
            if not item['verified']:
                lines.append('<form method="post" action="/domains/'+esc(item['id'])+'/verify">'
                             '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                             '<button type="submit">Verify DNS</button></form>')
            lines.append('</div>')
        lines.append('<form method="post" action="/domains/add"><label>Domain you administer '
                     '<input name="domain" maxlength="253" required placeholder="example.org"></label>'
                     '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                     '<button type="submit">Add domain</button></form>')
        lines.append('<form method="post" action="/auth/logout">'
                     '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                     '<button type="submit">Sign out</button></form>')
        return page('Owner domains', ''.join(lines))

    @api.post('/domains/add')
    async def add(req: Request):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields, sess)
        domain = fields.get('domain', '')
        if len(domain) > 253:
            raise HTTPException(422, detail='Invalid domain')
        claim = pg.create_domain(sess.subject, domain)
        proof = ('<p>Publish this DNS TXT record within 24 hours:</p>'
                 '<p><strong>Name</strong></p><p><code>'+esc(claim['txt_name'])+'</code></p>'
                 '<p><strong>Value</strong></p><p><code>'+esc(claim['txt_value'])+'</code></p>'
                 '<p><a href="/domains">Return to your domains</a></p>')
        return page('DNS verification challenge', proof)

    @api.post('/domains/{domain_id}/verify')
    async def verify(req: Request, domain_id: uuid.UUID):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields, sess)
        result = pg.verify_domain(sess.subject, domain_id, dns)
        return page('DNS verification result', '<p>'+esc(result['domain'])+': '
                    + ('Verified' if result['verified'] else 'Pending')+'</p>'
                    '<p><a href="/domains">Return to your domains</a></p>')

    @api.get('/domains/{domain_id}/monitor')
    def monitor(req: Request, domain_id: uuid.UUID):
        sess = current(req)
        keys = ops.list_keys(sess.subject,domain_id)
        recent = ops.recent(sess.subject,domain_id,limit=20)
        alerts = ops.list_alerts(sess.subject,domain_id,limit=20)
        lines = [('<p>Agent domain ID: <code>'+esc(domain_id.hex)+'</code></p>'
                  '<p>Private test endpoint: <code>http://127.0.0.1:8008</code>. '
                  'Do not expose this endpoint to the internet.</p>')]
        lines.append('<h3>Agent keys</h3>')
        for k in keys:
            lines.append('<div class="box"><strong>'+esc(k['label'])+'</strong>'
                         '<form method="post" action="/domains/'+esc(domain_id)+'/keys/'+esc(k['id'])+'/revoke">'
                         '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                         '<button type="submit">Revoke key</button></form></div>')
        lines.append('<form method="post" action="/domains/'+esc(domain_id)+'/keys">'
                     '<label>Key label <input name="label" maxlength="64" required></label>'
                     '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                     '<button type="submit">Issue agent key</button></form>')
        lines.append('<h3>Recent events ('+esc(recent['total_events'])+')</h3>')
        for ev in recent['events']:
            lines.append('<div class="box"><code>'+esc(ev['path_group'])+' '+esc(ev['status_code'])
                         +' '+esc(ev['agent_event_id'])+'</code></div>')
        lines.append('<h3>Alerts ('+esc(alerts['total_alerts'])+')</h3>')
        for alert in alerts['alerts']:
            lines.append('<div class="box"><strong>'+esc(alert['title'])+'</strong> - '
                         +esc(alert['status'])+'<p>'+esc(alert['explanation'])+'</p>')
            if alert['status'] == 'open':
                lines.append('<form method="post" action="/domains/'+esc(domain_id)
                             +'/alerts/'+esc(alert['id'])+'/acknowledge">'
                             '<input type="hidden" name="_csrf" value="'+esc(sess.csrf)+'">'
                             '<button type="submit">Acknowledge</button></form>')
            lines.append('</div>')
        lines.append('<p><a href="/domains">Back to domains</a></p>')
        return page('Domain monitoring', ''.join(lines))

    @api.post('/domains/{domain_id}/keys')
    async def issue_agent_key(req: Request, domain_id: uuid.UUID):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields,sess)
        key = ops.issue_key(sess.subject,domain_id,fields.get('label',''))
        return page('Agent key - copy once', '<p>This key is shown only once. Store it securely.</p>'
                    '<p><code>'+esc(key['agent_key'])+'</code></p>'
                    '<p><a href="/domains/'+esc(domain_id)+'/monitor">Back to monitoring</a></p>')

    @api.post('/domains/{domain_id}/keys/{key_id}/revoke')
    async def revoke_agent_key(req: Request, domain_id: uuid.UUID, key_id: uuid.UUID):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields,sess)
        ops.revoke_key(sess.subject,domain_id,key_id)
        return RedirectResponse('/domains/'+str(domain_id)+'/monitor',status_code=303)

    @api.post('/domains/{domain_id}/alerts/{alert_id}/acknowledge')
    async def acknowledge_alert(req: Request, domain_id: uuid.UUID, alert_id: uuid.UUID):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields,sess)
        ops.acknowledge(sess.subject,domain_id,alert_id)
        return RedirectResponse('/domains/'+str(domain_id)+'/monitor',status_code=303)

    @api.post('/auth/logout')
    async def logout(req: Request):
        sess = current(req)
        fields = await post_fields(req)
        check_csrf(fields, sess)
        state.logout(req.cookies.get(COOKIE))
        response = RedirectResponse('/', status_code=303)
        response.delete_cookie(COOKIE, path='/')
        return response

    @api.get('/health')
    def health():
        return {'status':'ok','mode':'private-auth0-browser-staging',
                'public_signup':False, 'telemetry_postgres_migrated':False, 'postgres_monitoring_pilot':True}

    return api


def factory() -> FastAPI:
    return create_web_app()
