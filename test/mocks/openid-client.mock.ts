/**
 * Ban gia lap `openid-client` cho unit test.
 *
 * `openid-client` v6 la ESM thuan, Jest (CommonJS) khong require duoc nen test se
 * that bai ngay khi mo file. Day la thu vien goi ra ngoai (accounts.haravan.com)
 * nen unit test khong bao gio can chay that no - chi can mot bien de import.
 */
export const discovery = jest.fn(async () => ({
  serverMetadata: () => ({}),
}));

export const buildAuthorizationUrl = jest.fn(
  () => new URL('https://accounts.haravan.com/connect/authorize'),
);

export const buildEndSessionUrl = jest.fn(
  () => new URL('https://accounts.haravan.com/connect/endsession'),
);

export const randomState = jest.fn(() => 'state');
export const randomNonce = jest.fn(() => 'nonce');
export const randomPKCECodeVerifier = jest.fn(() => 'verifier');
export const calculatePKCECodeChallenge = jest.fn(async () => 'challenge');

export const authorizationCodeGrant = jest.fn(async () => ({
  claims: () => ({ sub: 'mock-sub' }),
  access_token: 'mock-access-token',
}));

export const fetchUserInfo = jest.fn(async () => ({ sub: 'mock-sub' }));

export const skipSubjectCheck = Symbol('skipSubjectCheck');
