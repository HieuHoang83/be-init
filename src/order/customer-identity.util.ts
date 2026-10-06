export interface CustomerIdentity {
  haravanId?: number | null;
  email?: string | null;
  phone?: string | null;
  fullName?: string | null;
}

const VIRTUAL_CUSTOMER_EMAIL = /^(guest|noreply|no.?reply)([+._-].*)?@/i;
const VIRTUAL_CUSTOMER_NAME = /^(guest\b|khach le\b|khách lẻ\b|walk.?in\b)/i;

export function isVirtualCustomer(identity: CustomerIdentity): boolean {
  return (
    VIRTUAL_CUSTOMER_EMAIL.test(identity.email?.trim() ?? '') ||
    VIRTUAL_CUSTOMER_NAME.test(identity.fullName?.trim() ?? '')
  );
}

export function hasRealCustomerIdentity(identity: CustomerIdentity): boolean {
  if (isVirtualCustomer(identity)) return false;
  if (typeof identity.haravanId === 'number' && identity.haravanId > 0) {
    return true;
  }
  if (identity.email?.trim()) return true;
  return Boolean(identity.phone?.replace(/\D/g, ''));
}
