import { describe, expect, it } from 'bun:test'
import { basicAuth } from './index'
import { Elysia } from 'elysia'

export const req = (path: string, requestInit?: RequestInit) =>
  new Request(`http://localhost${path}`, requestInit)

const credentials = [{ username: 'admin', password: 'admin' }]
const userToken = Buffer.from('admin:admin').toString('base64')
const userInit = { headers: { Authorization: `Basic ${userToken}` } }
const bearerInit = {
  headers: { Authorization: `Bearer ${userToken}` },
}

describe('basicAuth', () => {
  const app = new Elysia()
    .use(
      basicAuth({
        credentials,
      })
    )
    .get('/private', () => 'private')
    .options('/private', () => 'public for preflight requests')

  it('sets WWW-Authenticate header on unauthorized requests', async () => {
    const anonResponse = await app.handle(req('/private'))
    expect(anonResponse.headers.get('WWW-Authenticate')).toEqual(
      'Basic realm="Secure Area"'
    )

    const userResponse = await app.handle(req('/private', userInit))
    expect(userResponse.headers.get('WWW-Authenticate')).toBeNull()
  })

  it('sets status code on unauthorized requests', async () => {
    const anonResponse = await app.handle(req('/private'))
    expect(anonResponse.status).toEqual(401)

    const userResponse = await app.handle(req('/private', userInit))
    expect(userResponse.status).toEqual(200)
  })

  it('protects non-existing routes', async () => {
    const anonRequest = req('/missing')
    expect((await app.handle(anonRequest)).status).toEqual(401)

    const userRequest = req('/missing', userInit)
    expect((await app.handle(userRequest)).status).toEqual(404)
  })

  it('rejects non-basic authorization headers', async () => {
    const bearerRequest = req('/private', bearerInit)
    expect((await app.handle(bearerRequest)).status).toEqual(401)
  })

  it('does not protect CORS preflight requests', async () => {
    const preflightRequest = req('/private', {
      method: 'OPTIONS',
      headers: {
        Origin: 'foreignhost',
        'Cross-Origin-Request-Method': 'GET',
      },
    })
    expect((await app.handle(preflightRequest)).status).toEqual(200)
  })
})

describe('basicAuth message customization', () => {
  const app = new Elysia().use(
    basicAuth({ credentials, unauthorizedMessage: 'Nope' })
  )

  it('allows for custom message', async () => {
    const anonResponse = await app.handle(req('/private'))
    expect(await anonResponse.text()).toEqual('Nope')
  })
})

describe('basicAuth realm customization', () => {
  const app = new Elysia()
    .use(basicAuth({ credentials, realm: 'Custom Realm' }))
    .get('/private', ({ store }) => store.basicAuthRealm)

  it('allows for custom realm', async () => {
    const anonResponse = await app.handle(req('/private'))
    expect(anonResponse.headers.get('WWW-Authenticate')).toEqual(
      'Basic realm="Custom Realm"'
    )
    const userResponse = await app.handle(req('/private', userInit))
    expect(await userResponse.text()).toEqual('Custom Realm')
  })
})

describe('basicAuth proxy customization', () => {
  const app = new Elysia()
    .use(
      basicAuth({
        credentials,
        header: 'Proxy-Authorization',
        unauthorizedStatus: 407,
      })
    )
    .get('/private', () => 'private')

  it('allows for custom status code', async () => {
    const anonResponse = await app.handle(req('/private'))
    expect(anonResponse.status).toEqual(407)
  })

  it('allows for custom header', async () => {
    const proxyRequest = req('/private', {
      headers: { 'Proxy-Authorization': `Basic ${userToken}` },
    })
    const proxyResponse = await app.handle(proxyRequest)
    expect(proxyResponse.status).toEqual(200)
  })
})

describe('basicAuth scope', () => {
  it('limits scope via path prefix', async () => {
    const app = new Elysia()
      .use(basicAuth({ credentials, scope: '/private' }))
      .get('/public', ({ store }) => store.basicAuthRealm)

    const publicResponse = await app.handle(req('/public'))
    expect(publicResponse.status).toEqual(200)
    expect(await publicResponse.text()).toEqual('')
  })

  it('limits scope via function', async () => {
    const app = new Elysia()
      .use(
        basicAuth({
          credentials,
          scope: ctx => ctx.request.url.endsWith('1234'),
        })
      )
      .get('/private/1234', () => 'private')

    expect((await app.handle(req('/private/1234'))).status).toEqual(401)
  })
})

describe('basicAuth multi-realm', () => {
  it('allows for non-overlapping realms', async () => {
    //realistically, these would be different credential pools
    const app = new Elysia()
      .use(
        basicAuth({
          credentials,
          realm: 'Realm A',
          scope: '/private/a',
        })
      )
      .use(
        basicAuth({
          credentials,
          realm: 'Realm B',
          scope: '/private/b',
        })
      )
      .get('/private/a', ({ store }) => store.basicAuthRealm)
      .get('/private/b', ({ store }) => store.basicAuthRealm)

    const realmAResponse = await app.handle(req('/private/a', userInit))
    expect(await realmAResponse.text()).toEqual('Realm A')

    const realmBResponse = await app.handle(req('/private/b', userInit))
    expect(await realmBResponse.text()).toEqual('Realm B')
  })
})
