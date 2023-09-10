Elysia Basic Auth
===

Basic auth for [Elysia.js](https://elysiajs.com/)

Install
---

```
bun add @eelkevdbos/elysia-basic-auth
```

Usage
---

Check out full sample at [`example`](example/index.ts) or check out the tests [`tests`](src/index.test.ts).

```ts
import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

const app = new Elysia()
  .use(
    basicAuth({
      credentials: [{ username: 'admin', password: 'admin' }],
      scope: "/private",
      realm: "Private Area",
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
```

Configuration
---

### credentials

`{ username: string, password: string }[]`

A list of credentials valid for authentication

### header

`string`

Default: `Authorization`

Header used for basic authentication.

### realm

`string`

Default: `Secure Area`

Realm used for basic authentication

### unauthorizedMessage

`string`

Default: `Unauthorized`

Response body for unauthorized requests

### unauthorizedStatus

`number`

Default: `401`

Response status for unauthorized requests

### scope

`string | (ctx: PreContext) => boolean`

Default: `/`

A string that will be compared with the current request path via `startsWith`.

Alternatively, a function can be provided that returns `true` if the context (and thereby request) is in the scope of the current basic auth protection space.

