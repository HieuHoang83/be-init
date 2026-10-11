/**
 * Claims lay tu id_token / userinfo cua Haravan Connect.
 *
 * Haravan tra them cac claim rieng ngoai chuan OIDC:
 *  - `orgid`: id shop ma nguoi dung dang nhap thuoc ve
 *  - `role`:  vai tro trong shop (owner, admin, staff...)
 */
export interface HaravanIdentity {
  /** Chu danh cua nguoi dung tren Haravan (truong `sub` cua id_token). */
  sub: string;
  email?: string;
  name?: string;
  phone?: string;
  /** Shop cua nguoi dung (`orgid`). */
  orgId?: number;
  /** Vai tro cua nguoi dung trong shop. */
  role?: string;
  /** Toan bo claims goc, giu lai de audit/debug. */
  claims: Record<string, unknown>;
}

/** Ket qua xu ly callback: danh tinh + noi frontend muon quay ve. */
export interface HaravanLoginResult {
  identity: HaravanIdentity;
  /** Do frontend gui len o `/haravan/auth/login?redirect_uri=`. */
  redirectUri?: string;
}

/** Session dang cho tra token sau khi nguoi dung dang nhap qua Haravan. */
export interface HaravanLoginSession {
  user: {
    id: string;
    name: string;
    phone?: string;
    avatar?: string;
    role?: string;
  };
  token: {
    access_token: string;
    refresh_token: string;
  };
  haravan: {
    sub: string;
    email?: string;
    orgId?: number;
    role?: string;
  };
}
