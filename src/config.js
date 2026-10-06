import 'dotenv/config';
export function getConfig() {
  const origin = process.env.APP_ORIGIN || 'https://localhost:3443';
  if (new URL(origin).origin !== origin || !origin.startsWith('https://')) throw Error('APP_ORIGIN must be an HTTPS origin without a trailing slash');
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.startsWith('REPLACE_') || Buffer.byteLength(secret) < 32) throw Error('Set JWT_SECRET to at least 32 random bytes');
  return { origin, secret, dbPath: process.env.DATABASE_PATH || './data/gateway.sqlite',
    production: process.env.NODE_ENV === 'production', githubClientId: process.env.GITHUB_CLIENT_ID,
    githubClientSecret: process.env.GITHUB_CLIENT_SECRET, trustProxy: Number(process.env.TRUST_PROXY_HOPS || 0) };
}
