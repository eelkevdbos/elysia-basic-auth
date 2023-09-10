import { timingSafeEqual } from 'crypto'
import Elysia, { PreContext } from 'elysia'

export type BasicAuthCredentials = {
  username: string
  password: string
}

type RequiredBasicAuthOptions = {
  credentials: BasicAuthCredentials[]
}

type ExtraBasicAuthOptions = {
  header: string
  realm: string
  unauthorizedMessage: string
  unauthorizedStatus: number
  scope: string | ((ctx: PreContext) => boolean)
}

export type BasicAuthOptions = RequiredBasicAuthOptions &
  Partial<ExtraBasicAuthOptions>
class BasicAuthError extends Error {
  constructor(
    readonly message: string,
    readonly realm: string
  ) {
    super(message)
    this.realm = realm
  }
}

const defaultOptions: ExtraBasicAuthOptions = {
  header: 'Authorization',
  realm: 'Secure Area',
  unauthorizedMessage: 'Unauthorized',
  unauthorizedStatus: 401,
  scope: '/',
}

/**
 * Timing safe string comparison
 */
function strSafeEqual(
  actual: string,
  expected: string,
  encoding: BufferEncoding = 'utf-8'
) {
  const actualBuffer = Buffer.from(actual, encoding)
  const expectedBuffer = Buffer.from(expected, encoding)
  const maxLength = Math.max(actualBuffer.byteLength, expectedBuffer.byteLength)
  return timingSafeEqual(
    //pads buffers to equal length, requirement for timingSafeEqual
    Buffer.concat([actualBuffer, Buffer.alloc(maxLength, 0)], maxLength),
    Buffer.concat([expectedBuffer, Buffer.alloc(maxLength, 0)], maxLength)
  )
}

/**
 * Credential factory with default values
 */
function newCredentials(
  attrs?: Partial<BasicAuthCredentials>
): BasicAuthCredentials {
  return { username: '', password: '', ...attrs }
}

/**
 * Checks credentials in timing safe, inspired by: https://github.com/jshttp/basic-auth
 */
function checkCredentials(
  challenge: BasicAuthCredentials,
  credentialsMap: Record<string, BasicAuthCredentials>
) {
  let valid = !!(challenge.username && challenge.password)
  const reference = credentialsMap[challenge.username]
  valid = strSafeEqual(challenge.username, reference?.username || '') && valid
  valid = strSafeEqual(challenge.password, reference?.password || '') && valid
  return valid
}

/**
 * Parses the Authorization header and returns a BasicAuthCredentials object
 */
function getCredentials(authHeader: string): BasicAuthCredentials {
  const [_, token] = authHeader.split(' ')
  const [username, password] = Buffer.from(token, 'base64')
    .toString('utf-8')
    .split(':')
  return newCredentials({ username, password })
}

/**
 * Extracts pathname from request url
 */
function getPath(request: Request) {
  return new URL(request.url).pathname
}

/**
 * Checks if the request is a CORS preflight request
 */
function isCORSPreflightRequest(request: Request) {
  return (
    request.method === 'OPTIONS' &&
    request.headers.has('Origin') &&
    request.headers.has('Cross-Origin-Request-Method')
  )
}

/**
 * Creates a predicate function for the scope option
 */
function newScopePredicate(scope: BasicAuthOptions['scope']) {
  switch (typeof scope) {
    case 'string':
      return (ctx: PreContext) => getPath(ctx.request).startsWith(scope)
    case 'function':
      return scope
    default:
      throw new Error(`Unhandled scope type: ${typeof scope}`)
  }
}

/**
 * Basic auth middleware
 */
export function basicAuth(userOptions: BasicAuthOptions) {
  const options: RequiredBasicAuthOptions & ExtraBasicAuthOptions = {
    ...defaultOptions,
    ...userOptions,
  }

  const credentialsMap = options.credentials.reduce((m, c) => {
    return { ...m, [c.username]: c }
  }, {})

  const inScope = newScopePredicate(options.scope)

  return (app: Elysia) =>
    app
      .state('basicAuthRealm', null as string | null)
      .addError({ BASIC_AUTH_ERROR: BasicAuthError })
      .onError(({ code, error }) => {
        if (code === 'BASIC_AUTH_ERROR' && error.realm === options.realm) {
          return new Response(options.unauthorizedMessage, {
            status: options.unauthorizedStatus,
            headers: { 'WWW-Authenticate': `Basic realm="${options.realm}"` },
          })
        }
      })
      .onRequest(ctx => {
        if (inScope(ctx) && !isCORSPreflightRequest(ctx.request)) {
          const authHeader = ctx.request.headers.get(options.header)
          if (!authHeader || !authHeader.toLowerCase().startsWith('basic ')) {
            throw new BasicAuthError('Invalid header', options.realm)
          }

          const credentials = getCredentials(authHeader)
          if (!checkCredentials(credentials, credentialsMap)) {
            throw new BasicAuthError('Invalid credentials', options.realm)
          }

          ctx.store.basicAuthRealm = options.realm
        }
      })
}
