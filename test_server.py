import asyncio
import os
import secrets
import unittest
import uuid
os.environ['RSS_LOCAL_DB'] = ':memory:'
os.environ['APP_ORIGIN'] = 'http://test'
os.environ['OWNER_EMAIL'] = 'owner@example.test'
os.environ['OWNER_PASSWORD'] = secrets.token_urlsafe(20)
import httpx
import server

class AccessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.life = server.lifespan(server.app)
        await self.life.__aenter__()
        self.clients = []
        self.owner = self.client()
        r = await self.owner.post('/api/login', json={'email': os.environ['OWNER_EMAIL'], 'password': os.environ['OWNER_PASSWORD']})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((await self.owner.get('/api/bookings')).status_code, 403)
        await self.owner.post('/api/password', json={'currentPassword': os.environ['OWNER_PASSWORD'], 'newPassword': secrets.token_urlsafe(20)})

    async def asyncTearDown(self):
        for c in self.clients:
            await c.aclose()
        await self.life.__aexit__(None, None, None)

    def client(self):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url='http://test', headers={'Origin': 'http://test'})
        self.clients.append(c)
        return c

    async def user(self, name, role):
        temporary = secrets.token_urlsafe(20)
        address = name+'@example.test'
        r = await self.owner.post('/api/users', json={'email': address, 'password': temporary, 'name': name, 'role': role})
        self.assertEqual(r.status_code, 201, r.text)
        user = r.json()
        c = self.client()
        await c.post('/api/login', json={'email': address, 'password': temporary})
        await c.post('/api/password', json={'currentPassword': temporary, 'newPassword': secrets.token_urlsafe(20)})
        return c, user

    def booking(self, address=''):
        return {'name': 'Test customer', 'phone': '9000000000', 'car': 'BMW', 'from': 'Prayagraj', 'to': 'Varanasi', 'date': '2026-11-15', 'time': '09:00', 'purpose': 'Wedding', 'total': 10000, 'advance': 1000, 'mode': 'UPI', 'customerEmail': address, 'requestId': str(uuid.uuid4())}

    async def test_customer_scope_and_staff_permissions(self):
        self.assertEqual((await self.client().get('/api/bookings')).status_code, 401)
        a, user_a = await self.user('customer-a', 'customer')
        b, _ = await self.user('customer-b', 'customer')
        employee, _ = await self.user('employee', 'employee')
        r = await employee.post('/api/bookings', json=self.booking(user_a['email']))
        self.assertEqual(r.status_code, 201)
        identifier = r.json()['id']
        self.assertEqual(len((await a.get('/api/bookings')).json()), 1)
        self.assertEqual((await b.get('/api/bookings')).json(), [])
        self.assertEqual((await b.post('/api/bookings/'+identifier+'/payments', json={'amount': 10, 'mode': 'UPI', 'requestId': str(uuid.uuid4())})).status_code, 403)
        self.assertEqual((await a.post('/api/bookings', json=self.booking())).status_code, 403)
        self.assertEqual((await employee.get('/api/users')).status_code, 403)
        self.assertEqual((await a.get('/api/customers')).status_code, 403)

    async def test_payment_idempotency_and_concurrency(self):
        booking = self.booking()
        first = await self.owner.post('/api/bookings', json=booking)
        again = await self.owner.post('/api/bookings', json=booking)
        self.assertEqual(first.json()['id'], again.json()['id'])
        path = '/api/bookings/'+first.json()['id']+'/payments'
        payload = {'amount': 5000, 'mode': 'Cash', 'requestId': str(uuid.uuid4())}
        results = await asyncio.gather(*[self.owner.post(path, json=payload) for _ in range(3)])
        self.assertTrue(all(r.status_code == 200 for r in results))
        rows = (await self.owner.get('/api/bookings')).json()
        self.assertEqual(len(rows[0]['payments']), 2)
        results = await asyncio.gather(*[self.owner.post(path, json={'amount': 3000, 'mode': 'Cash', 'requestId': str(uuid.uuid4())}) for _ in range(2)])
        self.assertEqual(sorted(r.status_code for r in results), [200, 409])
        self.assertEqual((await self.owner.post(path, json={'amount': .001, 'mode': 'Cash', 'requestId': str(uuid.uuid4())})).status_code, 422)

    async def test_reset_disable_logout_and_csrf(self):
        c, user = await self.user('employee', 'employee')
        reset = secrets.token_urlsafe(20)
        self.assertEqual((await self.owner.post('/api/users/'+user['id']+'/reset', json={'password': reset})).status_code, 200)
        self.assertEqual((await c.get('/api/me')).status_code, 401)
        login = await c.post('/api/login', json={'email': user['email'], 'password': reset})
        self.assertTrue(login.json()['mustChangePassword'])
        self.assertIn('HttpOnly', login.headers['set-cookie'])
        self.assertIn('SameSite=strict', login.headers['set-cookie'])
        self.assertEqual((await c.post('/api/logout', json={}, headers={'Origin': 'https://evil.test'})).status_code, 403)
        await self.owner.post('/api/users/'+user['id']+'/active', json={'active': False})
        self.assertEqual((await c.get('/api/me')).status_code, 401)
        await self.owner.post('/api/logout', json={})
        self.assertEqual((await self.owner.get('/api/me')).status_code, 401)

    async def test_rate_limit_and_secret_files(self):
        c = self.client()
        for _ in range(15):
            r = await c.post('/api/login', json={'email': 'missing@example.test', 'password': 'wrong'})
            if r.status_code == 429:
                break
            self.assertEqual(r.status_code, 401)
        self.assertEqual((await c.post('/api/login', json={'email': 'missing@example.test', 'password': 'wrong'})).status_code, 429)
        for name in ('server.py', '.env', 'test_server.py', 'render.yaml'):
            self.assertEqual((await c.get('/'+name)).status_code, 404)
        self.assertEqual((await c.get('/auth.js')).status_code, 200)

if __name__ == '__main__':
    unittest.main()
