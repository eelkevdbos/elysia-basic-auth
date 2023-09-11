import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

// use a file to supply credentials
new Elysia()
  .use(
    basicAuth({
      credentials: { file: 'fixtures/credentials' },
    })
  )
  .listen(3000)

// use an environment variable to supply credentials
process.env['MY_CREDENTIALS'] = 'admin:admin'
new Elysia()
  .use(
    basicAuth({
      credentials: { env: 'MY_CREDENTIALS' },
    })
  )
  .listen(3000)

// use an array of credentials
new Elysia()
  .use(
    basicAuth({
      credentials: [{ username: 'admin', password: 'admin' }],
    })
  )
  .listen(3000)
