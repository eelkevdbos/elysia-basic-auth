import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

new Elysia()
  .use(
    basicAuth({
      realm: 'Admin',
      scope: '/admin',
    })
  )
  .use(
    basicAuth({
      realm: 'User',
      scope: '/user',
    })
  )
  .get('/admin', ({ store }) => store.basicAuthRealm) // returns "Admin"
  .get('/user', ({ store }) => store.basicAuthRealm) // returns "User"
  .listen(3000)
