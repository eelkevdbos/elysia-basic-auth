import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

// use path prefix as scope
new Elysia()
  .use(
    basicAuth({
      scope: '/private',
    })
  )
  .get('/public', () => 'public')
  .get('/private/123', () => 'private by pathname prefix')
  .listen(3000)

// use a function to determine if a request is in scope
new Elysia()
  .use(
    basicAuth({
      scope: ctx => ctx.request.method === 'POST',
    })
  )
  .get('/', () => 'public')
  .post('/', () => 'private')
