import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

new Elysia()
  .use(basicAuth({ header: 'Proxy-Authorization', unauthorizedStatus: 407 }))
  .listen(3000)
