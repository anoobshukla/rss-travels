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

    async def test_imported_booking_with_unknown_fare(self):
        b = {'id': 'RSS-IMPORT-TEST', 'customerId': None, 'totalCents': None, 'paidCents': 110000, 'status': 'Pending', 'payments': [{'cents': 110000, 'mode': 'Not recorded', 'date': '', 'by': 'Excel import', 'requestId': 'source-advance'}]}
        server.db().create('bookings', b['id'], b)
        rows = (await self.owner.get('/api/bookings')).json()
        self.assertIsNone(rows[0]['total'])
        self.assertEqual(rows[0]['payments'][0]['amount'], 1100)
        result = await self.owner.post('/api/bookings/'+b['id']+'/payments', json={'amount': 100, 'mode': 'Cash', 'requestId': str(uuid.uuid4())})
        self.assertEqual(result.status_code, 409)

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

    async def test_employee_scope_and_driver_workflow(self):
        from unittest.mock import patch
        employee, eu = await self.user('creator', 'employee')
        other, _ = await self.user('other', 'employee')
        driver, du = await self.user('driver', 'driver')
        outsider, _ = await self.user('outsider', 'driver')
        payload = self.booking(); payload['driverId'] = du['id']
        response = await employee.post('/api/bookings', json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        b = response.json(); path = '/api/bookings/'+b['id']
        self.assertTrue(b['isMine']); self.assertTrue(b['canEdit'])
        hidden = (await other.get('/api/bookings')).json()[0]
        for key in ('total','payments','importSource','receipt'):
            self.assertNotIn(key, hidden)
        self.assertFalse(hidden['canEdit'])
        self.assertEqual((await other.post(path+'/payments', json={'amount':1,'mode':'Cash','requestId':str(uuid.uuid4())})).status_code,403)
        edit = {k:payload[k] for k in ('name','phone','car','from','to','date','time','purpose','total','driverId')}; edit['version']=b['version']
        self.assertEqual((await other.post(path+'/update',json=edit)).status_code,403)
        self.assertEqual((await employee.post(path+'/update',json={**edit,'total':500})).status_code,422)
        changed = await employee.post(path+'/update',json={**edit,'total':12000})
        self.assertEqual(changed.status_code,200,changed.text)
        self.assertEqual(changed.json()['payments'],b['payments'])
        self.assertEqual((await employee.post(path+'/update',json=edit)).status_code,409)
        self.assertEqual((await outsider.get('/api/bookings')).json(),[])
        self.assertNotIn('payments',(await driver.get('/api/bookings')).json()[0])
        self.assertEqual((await driver.post('/api/bookings',json=payload)).status_code,403)
        self.assertEqual((await driver.post(path+'/update',json=edit)).status_code,403)
        version=changed.json()['version']
        with patch('server.business_today',return_value=server.date(2026,11,14)):
            self.assertEqual((await driver.post(path+'/trip',json={'action':'start','version':version})).status_code,409)
        with patch('server.business_today',return_value=server.date(2026,11,15)):
            self.assertEqual((await outsider.post(path+'/trip',json={'action':'start','version':version})).status_code,403)
            self.assertEqual((await driver.post(path+'/trip',json={'action':'complete','version':version})).status_code,409)
            started=await driver.post(path+'/trip',json={'action':'start','version':version})
            self.assertEqual(started.status_code,200,started.text)
            self.assertEqual((await employee.post(path+'/update',json={**edit,'version':started.json()['version']})).status_code,409)
            finished=await other.post(path+'/trip',json={'action':'complete','version':started.json()['version']})
            self.assertEqual(finished.status_code,200,finished.text)
            self.assertEqual(finished.json()['status'],'Completed')
        self.assertEqual(server.db().get('bookings',b['id'])['createdBy'],eu['id'])

    async def test_booking_field_errors(self):
        payload=self.booking(); payload['phone']='8'
        r=await self.owner.post('/api/bookings',json=payload)
        self.assertEqual(r.status_code,422)
        self.assertIn('Contact number',r.json()['detail'])
        self.assertNotIn('assword',r.json()['detail'])

if __name__ == '__main__':
    unittest.main()
