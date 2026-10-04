"""RSS Travels authenticated API. Run with uvicorn server:app.

MongoDB is required for production. RSS_LOCAL_DB explicitly enables SQLite for
local development only; it cannot be used when RENDER or production is set.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, StrictBool

ROOT = Path(__file__).parent
PRODUCTION = bool(os.getenv('RENDER')) or os.getenv('APP_ENV') == 'production'
ORIGIN = os.getenv('APP_ORIGIN', 'http://127.0.0.1:4174').rstrip('/')
COOKIE = 'rss_session'
SESSION_SECONDS = 12 * 60 * 60
store = None

class Store:
    def __init__(self):
        self.lock = threading.RLock()
        local = os.getenv('RSS_LOCAL_DB')
        if local and not PRODUCTION:
            self.db = sqlite3.connect(local, check_same_thread=False)
            self.db.execute('CREATE TABLE IF NOT EXISTS docs (kind TEXT, id TEXT, version INTEGER, body TEXT, PRIMARY KEY(kind,id))')
            self.mongo = False
        else:
            uri = os.getenv('MONGODB_URI')
            if not uri:
                raise RuntimeError('Database configuration required')
            from pymongo import MongoClient
            self.client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            self.db = self.client[os.getenv('MONGODB_DB', 'rss_travels')]
            self.client.admin.command('ping')
            self.mongo = True

    def get(self, kind, key):
        if self.mongo:
            value = self.db[kind].find_one({'_id': key})
            if value:
                value.pop('_id', None)
            return value
        with self.lock:
            row = self.db.execute('SELECT body FROM docs WHERE kind=? AND id=?', (kind, key)).fetchone()
            return json.loads(row[0]) if row else None

    def all(self, kind):
        if self.mongo:
            return [{k: v for k, v in row.items() if k != '_id'} for row in self.db[kind].find({})]
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute('SELECT body FROM docs WHERE kind=?', (kind,))]

    def create(self, kind, key, value):
        value = {**value, 'version': 1}
        if self.mongo:
            from pymongo.errors import DuplicateKeyError
            try:
                self.db[kind].insert_one({'_id': key, **value})
                return True
            except DuplicateKeyError:
                return False
        with self.lock:
            try:
                self.db.execute('INSERT INTO docs VALUES (?,?,?,?)', (kind, key, 1, json.dumps(value)))
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def replace(self, kind, key, value, version):
        value = {**value, 'version': version + 1}
        if self.mongo:
            return self.db[kind].replace_one({'_id': key, 'version': version}, {'_id': key, **value}).modified_count == 1
        with self.lock:
            result = self.db.execute('UPDATE docs SET version=?,body=? WHERE kind=? AND id=? AND version=?', (version + 1, json.dumps(value), kind, key, version))
            self.db.commit()
            return result.rowcount == 1

    def delete(self, kind, key):
        if self.mongo:
            self.db[kind].delete_one({'_id': key})
        else:
            with self.lock:
                self.db.execute('DELETE FROM docs WHERE kind=? AND id=?', (kind, key))
                self.db.commit()

def email(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise HTTPException(422, 'Enter a valid email address.')
    return value

def password_hash(value, salt=None):
    if not 12 <= len(value) <= 128:
        raise HTTPException(422, 'Use a password of 12–128 characters.')
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', value.encode(), bytes.fromhex(salt), 600000).hex()
    return salt + ':' + digest

def password_matches(value, encoded):
    if not 12 <= len(value) <= 128:
        return False
    return hmac.compare_digest(password_hash(value, encoded.split(':')[0]), encoded)

DUMMY_HASH = password_hash('not-an-account-password')

def public_user(user):
    return {k: user[k] for k in ('id', 'email', 'name', 'role', 'active', 'mustChangePassword')}

def db():
    if store is None:
        raise HTTPException(503, 'Login is not ready yet. The owner needs to finish database setup.')
    return store

def audit(actor, action, target):
    key = secrets.token_hex(16)
    db().create('audit_logs', key, {'id': key, 'actor': actor, 'action': action, 'target': target, 'at': time.time()})

def throttle(key):
    # Database-backed limits survive restarts and cover multiple server instances.
    bucket = int(time.time() // 900)
    key = hashlib.sha256(f'{bucket}:{key}'.encode()).hexdigest()
    for _ in range(20):
        current = db().get('login_limits', key)
        if not current:
            if db().create('login_limits', key, {'count': 1, 'expires': (bucket + 2) * 900}):
                return
        else:
            if current['count'] >= 15:
                raise HTTPException(429, 'Too many attempts. Please try again in 15 minutes.')
            if db().replace('login_limits', key, {**current, 'count': current['count'] + 1}, current['version']):
                return
    raise HTTPException(429, 'Please try again shortly.')

@asynccontextmanager
async def lifespan(app):
    global store
    try:
        if PRODUCTION and not ORIGIN.startswith('https://'):
            raise RuntimeError('HTTPS origin required')
        store = Store()
        owner_email = os.getenv('OWNER_EMAIL')
        owner_password = os.getenv('OWNER_PASSWORD')
        if owner_email and owner_password:
            owner_email = email(owner_email)
            if not store.get('users', owner_email):
                store.create('users', owner_email, {'id': secrets.token_hex(16), 'email': owner_email, 'name': os.getenv('OWNER_NAME', 'Owner'), 'role': 'owner', 'active': True, 'mustChangePassword': True, 'passwordHash': password_hash(owner_password), 'sessionVersion': 1})
        # Expired records do not grant access; clean them up at startup as well.
        for kind in ('sessions', 'login_limits'):
            if store.mongo:
                store.db[kind].delete_many({'expires': {'$lt': time.time()}})
    except Exception as error:
        store = None
        # Report only fixed diagnostic categories, never exception messages: Mongo
        # exceptions can contain the connection URI, username or other secrets.
        from pymongo.errors import ServerSelectionTimeoutError, OperationFailure, ConfigurationError, InvalidURI
        if isinstance(error, ServerSelectionTimeoutError):
            reason = 'DATABASE_UNREACHABLE: Check Atlas Network Access for this service outbound IP ranges and cluster availability.'
        elif isinstance(error, OperationFailure):
            reason = 'DATABASE_AUTH_OR_PERMISSION: Check the database username, rotated password, and read/write permissions.'
        elif isinstance(error, (ConfigurationError, InvalidURI)):
            reason = 'DATABASE_CONNECTION_FORMAT: Check the connection string format and cluster DNS.'
        elif isinstance(error, HTTPException):
            reason = 'OWNER_CONFIGURATION: Check the owner email and password length (12-128 characters).'
        else:
            reason = 'CONFIGURATION_REQUIRED: Check MONGODB_URI and the HTTPS APP_ORIGIN.'
        print('RSS Travels setup incomplete. ' + reason, flush=True)
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

@app.exception_handler(RequestValidationError)
async def invalid_input(request, error):
    labels = {'phone': 'Contact number', 'secondary': 'Secondary contact', 'from': 'Pickup location', 'to': 'Drop location', 'requestId': 'Request identifier'}
    messages = [labels.get(str(e['loc'][-1]), str(e['loc'][-1])) + ': ' + e['msg'] for e in error.errors()]
    return JSONResponse({'detail': '; '.join(messages)}, status_code=422)

@app.middleware('http')
async def security(request, call_next):
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and request.headers.get('origin') != ORIGIN:
        return JSONResponse({'detail': 'Request origin not allowed.'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if PRODUCTION:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

def session_key(request):
    token = request.cookies.get(COOKIE, '')
    return hashlib.sha256(token.encode()).hexdigest()

def current_user(request, allow_change=False):
    session = db().get('sessions', session_key(request))
    if not session or session['expires'] < time.time():
        raise HTTPException(401, 'Please sign in.')
    user = db().get('users', session['email'])
    if not user or not user['active'] or user['sessionVersion'] != session['sessionVersion']:
        raise HTTPException(401, 'Please sign in again.')
    if user['mustChangePassword'] and not allow_change:
        raise HTTPException(403, 'Change your temporary password first.')
    return user

def staff(request, owner=False):
    user = current_user(request)
    if user['role'] not in (('owner',) if owner else ('owner', 'employee')):
        raise HTTPException(403, 'You do not have permission for this action.')
    return user

def start_session(user, response):
    token = secrets.token_urlsafe(32)
    db().create('sessions', hashlib.sha256(token.encode()).hexdigest(), {'email': user['email'], 'sessionVersion': user['sessionVersion'], 'expires': time.time() + SESSION_SECONDS})
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=PRODUCTION, samesite='strict', path='/')

class Login(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)

class NewUser(Login):
    name: str = Field(min_length=1, max_length=120)
    role: str

class PasswordChange(BaseModel):
    currentPassword: str = Field(max_length=128)
    newPassword: str = Field(min_length=12, max_length=128)

class ResetPassword(BaseModel):
    password: str = Field(min_length=12, max_length=128)

class Active(BaseModel):
    active: StrictBool

class Booking(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    secondary: str = Field(default='', max_length=20)
    car: str = Field(min_length=1, max_length=120)
    from_: str = Field(alias='from', min_length=1, max_length=200)
    to: str = Field(min_length=1, max_length=200)
    date: date
    time: str = Field(pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
    purpose: str = Field(min_length=1, max_length=120)
    total: float = Field(ge=0, le=10000000, allow_inf_nan=False)
    advance: float = Field(ge=0, le=10000000, allow_inf_nan=False)
    mode: str
    source: str = Field(default='', max_length=200)
    driverId: str = Field(default='', max_length=64)
    customerEmail: str = Field(default='', max_length=254)
    requestId: str = Field(pattern=r'^[a-f0-9-]{36}$')

class Payment(BaseModel):
    amount: float = Field(gt=0, le=10000000, allow_inf_nan=False)
    mode: str
    requestId: str = Field(pattern=r'^[a-f0-9-]{36}$')

def cents(value):
    from decimal import Decimal
    v = Decimal(str(value)) * 100
    if v != v.to_integral_value():
        raise HTTPException(422, 'Amounts can have at most two decimal places.')
    return int(v)

def mode(value):
    if value not in ('UPI', 'Cash', 'Bank transfer'):
        raise HTTPException(422, 'Choose a supported payment mode.')
    return value

def business_today():
    return datetime.now(ZoneInfo('Asia/Kolkata')).date()

def manages(user, b):
    return user['role'] == 'owner' or (user['role'] == 'employee' and b.get('createdBy') == user['id'])

def booking_view(b, user=None):
    financial = user is None or user['role'] in ('owner', 'customer') or manages(user, b)
    keys = ('id', 'name', 'phone', 'secondary', 'car', 'from', 'to', 'date', 'time', 'purpose', 'status', 'driverId', 'driverName', 'startedAt', 'completedAt')
    result = {k: b.get(k, '') for k in keys}
    result.update(deleted=bool(b.get('deletedAt')), canDelete=user is not None and user['role'] == 'owner' and not b.get('deletedAt') and b['status'] != 'In progress', version=b.get('version', 1), customerId=b.get('customerId'), financialVisible=financial,
                  isMine=user is not None and b.get('createdBy') == user['id'],
                  canEdit=user is not None and not b.get('deletedAt') and manages(user, b) and b['status'] not in ('In progress', 'Completed', 'Cancelled'))
    operator = not b.get('deletedAt') and user is not None and (user['role'] in ('owner', 'employee') or (user['role'] == 'driver' and b.get('driverId') == user['id']))
    on_date = b.get('date') == str(business_today())
    result['canStart'] = operator and on_date and b['status'] in ('Pending', 'Confirmed')
    result['canComplete'] = operator and on_date and b['status'] == 'In progress'
    if financial:
        result.update(total=b['totalCents'] / 100 if b.get('totalCents') is not None else None,
                      receipt=b.get('receipt', ''), importSource=b.get('importSource'),
                      payments=[{k: v for k, v in p.items() if k not in ('cents', 'requestId')} | {'amount': p['cents'] / 100} for p in b['payments']],
                      canPay=user is not None and not b.get('deletedAt') and manages(user, b))
    if user and user['role'] in ('owner', 'employee'):
        result['source'] = b.get('source', '')
    return result

def valid_driver(identifier):
    if not identifier:
        return ''
    user = target_user(identifier)
    if user['role'] != 'driver' or not user['active']:
        raise HTTPException(422, 'Select an active driver.')
    return user['name']

@app.get('/api/drivers')
def drivers(request: Request):
    staff(request)
    return [{'id': u['id'], 'name': u['name']} for u in db().all('users') if u['role'] == 'driver' and u['active']]

@app.api_route('/api/health', methods=['GET', 'HEAD'])
def health():
    return {'ready': store is not None, 'database': os.getenv('MONGODB_DB', 'rss_travels') if store else None}

@app.post('/api/login')
def login(body: Login, request: Request):
    address = email(body.email)
    throttle('account:' + address)
    throttle('ip:' + (request.client.host if request.client else 'unknown'))
    user = db().get('users', address)
    valid = password_matches(body.password, user['passwordHash'] if user else DUMMY_HASH)
    if not valid or not user or not user['active']:
        raise HTTPException(401, 'Email or password is incorrect.')
    response = JSONResponse(public_user(user))
    start_session(user, response)
    return response

@app.post('/api/logout')
def logout(request: Request):
    db().delete('sessions', session_key(request))
    response = JSONResponse({'ok': True})
    response.delete_cookie(COOKIE, path='/')
    return response

@app.get('/api/me')
def me(request: Request):
    return public_user(current_user(request, True))

@app.post('/api/password')
def change_password(body: PasswordChange, request: Request):
    user = current_user(request, True)
    throttle('password:' + user['id'])
    if not password_matches(body.currentPassword, user['passwordHash']):
        raise HTTPException(400, 'Current password is incorrect.')
    if body.newPassword == body.currentPassword:
        raise HTTPException(422, 'Choose a different password.')
    updated = {**user, 'passwordHash': password_hash(body.newPassword), 'mustChangePassword': False, 'sessionVersion': user['sessionVersion'] + 1}
    if not db().replace('users', user['email'], updated, user['version']):
        raise HTTPException(409, 'Account changed. Please sign in again.')
    db().delete('sessions', session_key(request))
    response = JSONResponse(public_user(updated))
    start_session(updated, response)
    audit(user['id'], 'password_changed', user['id'])
    return response

@app.get('/api/users')
def users(request: Request):
    staff(request, True)
    return [public_user(u) for u in db().all('users')]

@app.get('/api/customers')
def customers(request: Request):
    staff(request)
    return [{'id': u['id'], 'email': u['email'], 'name': u['name']} for u in db().all('users') if u['role'] == 'customer' and u['active']]

@app.post('/api/users', status_code=201)
def create_user(body: NewUser, request: Request):
    actor = staff(request, True)
    if body.role not in ('owner', 'employee', 'customer', 'driver') or not body.name.strip():
        raise HTTPException(422, 'Choose a valid name and role.')
    user = {'id': secrets.token_hex(16), 'email': email(body.email), 'name': body.name.strip(), 'role': body.role, 'passwordHash': password_hash(body.password), 'active': True, 'mustChangePassword': True, 'sessionVersion': 1}
    if not db().create('users', user['email'], user):
        raise HTTPException(409, 'An account already uses this email.')
    audit(actor['id'], 'account_created', user['id'])
    return public_user(user)

def target_user(identifier):
    user = next((u for u in db().all('users') if u['id'] == identifier), None)
    if not user:
        raise HTTPException(404, 'Account not found.')
    return user

@app.post('/api/users/{identifier}/reset')
def reset_password(identifier: str, body: ResetPassword, request: Request):
    actor = staff(request, True)
    user = target_user(identifier)
    if actor['id'] == user['id']:
        raise HTTPException(400, 'Use Change password for your own account.')
    updated = {**user, 'passwordHash': password_hash(body.password), 'mustChangePassword': True, 'sessionVersion': user['sessionVersion'] + 1}
    if not db().replace('users', user['email'], updated, user['version']):
        raise HTTPException(409, 'Account changed. Try again.')
    audit(actor['id'], 'password_reset', identifier)
    return {'ok': True}

@app.post('/api/users/{identifier}/active')
def set_active(identifier: str, body: Active, request: Request):
    actor = staff(request, True)
    user = target_user(identifier)
    if user['role'] == 'owner':
        raise HTTPException(400, 'Owner accounts cannot be disabled here.')
    if not db().replace('users', user['email'], {**user, 'active': body.active, 'sessionVersion': user['sessionVersion'] + 1}, user['version']):
        raise HTTPException(409, 'Account changed. Try again.')
    audit(actor['id'], 'account_enabled' if body.active else 'account_disabled', identifier)
    return {'ok': True}

@app.get('/api/bookings')
def list_bookings(request: Request, deleted: bool = False):
    user = current_user(request)
    if deleted and user['role'] != 'owner':
        raise HTTPException(403, 'Only owners can view deleted bookings.')
    records = [b for b in db().all('bookings') if bool(b.get('deletedAt')) == deleted]
    if user['role'] == 'customer':
        records = [b for b in records if b.get('customerId') == user['id']]
    elif user['role'] == 'driver':
        records = [b for b in records if b.get('driverId') == user['id']]
    return [booking_view(b, user) for b in records]

@app.post('/api/bookings', status_code=201)
def create_booking(body: Booking, request: Request):
    actor = staff(request)
    if body.date <= business_today():
        raise HTTPException(422, 'New bookings are available from tomorrow onward (India time).')
    driver_name = valid_driver(body.driverId)
    total, advance = cents(body.total), cents(body.advance)
    if advance > total:
        raise HTTPException(422, 'Advance cannot exceed the agreed fare.')
    mode(body.mode)
    for number in (body.phone, body.secondary):
        if number and not re.fullmatch(r'[0-9+ ()-]{7,20}', number):
            raise HTTPException(422, 'Contact numbers need 7–20 valid characters.')
    values = body.model_dump(by_alias=True, mode='json')
    for field in ('name', 'car', 'from', 'to', 'purpose'):
        values[field] = values[field].strip()
        if not values[field]:
            raise HTTPException(422, 'Required fields cannot be blank.')
    customer_id = None
    if body.customerEmail:
        customer = db().get('users', email(body.customerEmail))
        if not customer or customer['role'] != 'customer' or not customer['active']:
            raise HTTPException(422, 'Select an active customer account.')
        customer_id = customer['id']
    identifier = 'RSS-' + hashlib.sha256((actor['id'] + body.requestId).encode()).hexdigest()[:16].upper()
    existing = db().get('bookings', identifier)
    if existing:
        return booking_view(existing, actor)
    for field in ('total', 'advance', 'mode', 'customerEmail'):
        values.pop(field)
    booking = {**values, 'id': identifier, 'customerId': customer_id, 'totalCents': total, 'paidCents': advance, 'status': 'Confirmed', 'createdBy': actor['id'], 'driverName': driver_name, 'payments': [{'cents': advance, 'mode': body.mode, 'date': str(business_today()), 'by': actor['name'], 'requestId': body.requestId}] if advance else []}
    if db().create('bookings', identifier, booking):
        audit(actor['id'], 'booking_created', identifier)
    return booking_view(db().get('bookings', identifier), actor)

@app.post('/api/bookings/{identifier}/payments')
def payment(identifier: str, body: Payment, request: Request):
    actor = staff(request)
    amount = cents(body.amount)
    mode(body.mode)
    for _ in range(10):
        booking = db().get('bookings', identifier)
        if not booking or booking.get('deletedAt'):
            raise HTTPException(404, 'Booking not found.')
        if not manages(actor, booking):
            raise HTTPException(403, 'You can only collect payments for bookings you created.')
        if any(p['requestId'] == body.requestId for p in booking['payments']):
            return booking_view(booking, actor)
        if booking.get('totalCents') is None:
            raise HTTPException(409, 'Set the agreed fare before recording another payment.')
        if booking['status'] == 'Cancelled' or amount > booking['totalCents'] - booking['paidCents']:
            raise HTTPException(409, 'Balance changed or payment exceeds the remaining amount. Refresh the booking.')
        updated = {**booking, 'paidCents': booking['paidCents'] + amount, 'payments': booking['payments'] + [{'cents': amount, 'mode': body.mode, 'date': str(business_today()), 'by': actor['name'], 'requestId': body.requestId}]}
        if db().replace('bookings', identifier, updated, booking['version']):
            audit(actor['id'], 'payment_recorded', identifier)
            return booking_view(updated, actor)
    raise HTTPException(409, 'Another payment is being saved. Please refresh and retry.')

class BookingEdit(BaseModel):
    version: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=120)
    phone: str = Field(default='', max_length=20)
    secondary: str = Field(default='', max_length=20)
    car: str = Field(default='', max_length=120)
    from_: str = Field(alias='from', max_length=200)
    to: str = Field(default='', max_length=200)
    date: date
    time: str = Field(default='', pattern=r'^$|^([01]\d|2[0-3]):[0-5]\d$')
    purpose: str = Field(max_length=120)
    total: float | None = Field(default=None, ge=0, le=10000000, allow_inf_nan=False)
    source: str = Field(default='', max_length=200)
    driverId: str = Field(default='', max_length=64)

@app.post('/api/bookings/{identifier}/update')
def update_booking(identifier: str, body: BookingEdit, request: Request):
    actor = staff(request)
    b = db().get('bookings', identifier)
    if not b or b.get('deletedAt'):
        raise HTTPException(404, 'Booking not found.')
    if not manages(actor, b):
        raise HTTPException(403, 'You can only edit bookings you created.')
    if b['status'] in ('In progress', 'Completed', 'Cancelled'):
        raise HTTPException(409, 'Only upcoming bookings can be edited.')
    if str(body.date) != b['date'] and body.date <= business_today():
        raise HTTPException(422, 'Choose tomorrow or a later travel date (India time).')
    if not body.name.strip():
        raise HTTPException(422, 'Customer name cannot be blank.')
    for number in (body.phone, body.secondary):
        if number and (not re.fullmatch(r'[0-9+ ()-]{7,20}', number)):
            raise HTTPException(422, 'Contact numbers need 7–20 characters using digits, spaces, +, - or parentheses.')
    total = cents(body.total) if body.total is not None else None
    if total is not None and total < b['paidCents']:
        raise HTTPException(422, 'Agreed fare cannot be less than payments already received.')
    values = body.model_dump(by_alias=True, mode='json')
    values.pop('total'); values.pop('version')
    driver_name = valid_driver(body.driverId) if body.driverId != b.get('driverId', '') else b.get('driverName', '')
    updated = {**b, **values, 'totalCents': total, 'driverName': driver_name}
    updated = with_owner_notice(actor, b, updated, 'updated')
    if not db().replace('bookings', identifier, updated, body.version):
        raise HTTPException(409, 'Booking changed. Refresh and try again.')
    audit(actor['id'], 'booking_updated', identifier)
    return booking_view(db().get('bookings', identifier), actor)

class TripAction(BaseModel):
    action: str
    version: int = Field(ge=1)

@app.post('/api/bookings/{identifier}/trip')
def trip(identifier: str, body: TripAction, request: Request):
    actor = current_user(request)
    b = db().get('bookings', identifier)
    if not b or b.get('deletedAt'):
        raise HTTPException(404, 'Booking not found.')
    if actor['role'] not in ('owner', 'employee') and not (actor['role'] == 'driver' and b.get('driverId') == actor['id']):
        raise HTTPException(403, 'You cannot operate this trip.')
    if b['date'] != str(business_today()):
        raise HTTPException(409, 'Trips can only start and end on the booking date (India time).')
    if body.action == 'start' and b['status'] in ('Pending', 'Confirmed'):
        changes = {'status': 'In progress', 'startedAt': datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(), 'startedBy': actor['id']}
    elif body.action == 'complete' and b['status'] == 'In progress':
        changes = {'status': 'Completed', 'completedAt': datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(), 'completedBy': actor['id']}
    else:
        raise HTTPException(409, 'Trip status changed or this action is not available.')
    updated = with_owner_notice(actor, b, {**b, **changes}, 'started' if body.action == 'start' else 'completed')
    if not db().replace('bookings', identifier, updated, body.version):
        raise HTTPException(409, 'Booking changed. Refresh and try again.')
    audit(actor['id'], 'trip_'+body.action, identifier)
    return booking_view(db().get('bookings', identifier), actor)

def with_owner_notice(actor, old, updated, action):
    if actor['role'] != 'owner':
        return updated
    recipients = sorted({old.get('createdBy'), old.get('customerId'), old.get('driverId'), updated.get('driverId')} - {None, '', 'excel-import', actor['id']})
    if not recipients:
        return updated
    notice = {'id': old['id'] + ':' + str(old['version'] + 1), 'bookingId': old['id'], 'recipients': recipients,
              'message': 'An owner ' + action + ' booking ' + old['id'] + '.', 'at': datetime.now(ZoneInfo('Asia/Kolkata')).isoformat()}
    return {**updated, 'ownerUpdates': old.get('ownerUpdates', []) + [notice]}

def notifications_for(user):
    notices = [n for b in db().all('bookings') for n in b.get('ownerUpdates', []) if user['id'] in n['recipients']]
    return sorted(notices, key=lambda n: n['at'], reverse=True)[:100]

@app.get('/api/notifications')
def notifications(request: Request):
    user = current_user(request)
    return [{k: n[k] for k in ('id', 'bookingId', 'message', 'at')} | {'read': db().get('notification_reads', user['id']+':'+n['id']) is not None} for n in notifications_for(user)]

class ReadNotifications(BaseModel):
    ids: list[str] = Field(max_length=100)

@app.post('/api/notifications/read')
def read_notifications(body: ReadNotifications, request: Request):
    user = current_user(request)
    allowed = {n['id'] for n in notifications_for(user)}
    for identifier in set(body.ids) & allowed:
        db().create('notification_reads', user['id']+':'+identifier, {'at': time.time()})
    return {'ok': True}

class VersionAction(BaseModel):
    version: int = Field(ge=1)

@app.post('/api/bookings/{identifier}/delete')
def delete_booking(identifier: str, body: VersionAction, request: Request):
    actor = staff(request, True)
    b = db().get('bookings', identifier)
    if not b or b.get('deletedAt'):
        raise HTTPException(404, 'Booking not found.')
    if b['status'] == 'In progress':
        raise HTTPException(409, 'End the active trip before deleting its booking.')
    updated = with_owner_notice(actor, b, {**b, 'deletedAt': datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(), 'deletedBy': actor['id']}, 'deleted')
    if not db().replace('bookings', identifier, updated, body.version):
        raise HTTPException(409, 'Booking changed. Refresh and try again.')
    audit(actor['id'], 'booking_deleted', identifier)
    return {'ok': True}

@app.post('/api/bookings/{identifier}/restore')
def restore_booking(identifier: str, body: VersionAction, request: Request):
    actor = staff(request, True)
    b = db().get('bookings', identifier)
    if not b or not b.get('deletedAt'):
        raise HTTPException(404, 'Deleted booking not found.')
    updated = {**b}; updated.pop('deletedAt'); updated.pop('deletedBy', None)
    updated = with_owner_notice(actor, b, updated, 'restored')
    if not db().replace('bookings', identifier, updated, body.version):
        raise HTTPException(409, 'Booking changed. Refresh and try again.')
    audit(actor['id'], 'booking_restored', identifier)
    return {'ok': True}

class RoleChange(BaseModel):
    role: str

@app.post('/api/users/{identifier}/role')
def change_role(identifier: str, body: RoleChange, request: Request):
    actor = staff(request, True)
    user = target_user(identifier)
    if user['role'] == 'owner' or body.role not in ('customer', 'employee', 'driver'):
        raise HTTPException(422, 'Only customer, employee and driver roles can be changed here.')
    if not db().replace('users', user['email'], {**user, 'role': body.role, 'sessionVersion': user['sessionVersion']+1}, user['version']):
        raise HTTPException(409, 'Account changed. Try again.')
    audit(actor['id'], 'role_changed_to_'+body.role, identifier)
    return {'ok': True}

@app.api_route('/', methods=['GET', 'HEAD'])
def index():
    return FileResponse(ROOT / 'index.html')

@app.get('/{asset}')
def asset(asset: str):
    if asset not in ('app.js', 'styles.css', 'auth.js'):
        raise HTTPException(404)
    return FileResponse(ROOT / asset)
