import { Elysia } from 'elysia'

import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

new Elysia()
  .use(
    basicAuth({
      credentials: [{ username: 'admin', password: 'admin' }],
      scope: '/private',
      realm: 'Private Area',
    })
  )
  // out of scope path
  .get('/public', () => 'public')
  // pathname matches scope
  .get('/private/123', () => 'private by pathname prefix')
  // access to realm within a handler, returns 'Private Area'
  .get('/private/realm-stored', ({ store }) => store.basicAuthRealm)
  // cors preflights are public by default
  .options('/private/123', () => 'public for CORS preflight requests')
  .listen(3000)
