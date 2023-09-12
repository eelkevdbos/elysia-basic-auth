Elysia Basic Auth ![example workflow](https://github.com/eelkevdbos/elysia-basic-auth/actions/workflows/test.yml/badge.svg)
===

Basic auth for [Elysia.js](https://elysiajs.com/).

- Uses the `request` event to handle authentication, decoupling authentication from route existence, limiting url [fuzzing](https://owasp.org/www-project-web-security-testing-guide/latest/6-Appendix/C-Fuzzing) exposure.
- Compares credentials timing-attack safely via `crypto.timingSafeEqual`.
- Exposes the authenticated realm via `store.basicAuthRealm`.
- Optionally, bypasses CORS preflight requests, blocks them by default (in scope).
- Loads credentials from:
  - A list of `{username, password}` objects.
  - A file containing `username:password` pairs, separated by `newlines`.
  - An environment variable containing `username:password` pairs, separated by `semicolons`.

Future releases may include:
- Support for hashed passwords.

Install
---

```
bun add @eelkevdbos/elysia-basic-auth
```

Usage
---

Check out full samples at [`examples`](./examples/) or check out the tests [`tests`](src/index.test.ts).

```ts
import { Elysia } from 'elysia'
import { basicAuth } from '@eelkevdbos/elysia-basic-auth'

process.env["BASIC_AUTH_CREDENTIALS"] = "admin:admin;user:user"

new Elysia()
  .use(basicAuth())
  // all routes are protected by default
  .get("/", () => "private")
  // access to realm within a handler
  .get('/private/realm-stored', ({ store }) => store.basicAuthRealm)
  .listen(3000)
```

Configuration
---

### credentials

`{ file: string } | { env: string } | { username: string, password: string }[]`

A list of credentials valid for authentication, a file with credential pairs separated by newlines, or an environment variable with credential pairs separated by semicolons.

Default: `{ env: "BASIC_AUTH_CREDENTIALS" }`

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

`string | string[] | (ctx: PreContext) => boolean`

Default: `/`

A string or list of strings that will be compared with the current request path via `startsWith`.

Alternatively, a function can be provided that returns `true` if the context (and thereby request) is in the scope of the current basic auth protection space.

### skipCorsPreflight

`boolean`

Default: `false`

A boolean that determines whether CORS preflight requests should be skipped.

### enabled

`boolean`

Default: `true`

A boolean that determines whether basic auth should be enabled. If set to `false`, will disable the `onRequest` handler.
