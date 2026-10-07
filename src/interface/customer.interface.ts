export interface HaravanCustomerAddress {
  id?: number;
  customer_id?: number;
  address1?: string | null;
  address2?: string | null;
  city?: string | null;
  company?: string | null;
  country?: string | null;
  country_code?: string | null;
  country_name?: string | null;
  default?: boolean;
  first_name?: string | null;
  last_name?: string | null;
  name?: string | null;
  phone?: string | null;
  province?: string | null;
  province_code?: string | null;
  zip?: string | null;
  district?: string | null;
  district_code?: string | null;
  ward?: string | null;
  ward_code?: string | null;
}

/**
 * Customer resource — scopes `com.read_customers`, `com.write_customers`.
 * Nguồn: https://docs.haravan.com/docs/omni-apis/customer/
 */
export interface HaravanCustomer {
  id?: number;
  email?: string | null;
  phone?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  accepts_marketing?: boolean;
  addresses?: HaravanCustomerAddress[];
  default_address?: HaravanCustomerAddress | null;
  note?: string | null;
  tags?: string | null;
  state?: string;
  verified_email?: boolean;
  orders_count?: number;
  total_spent?: number;
  total_paid?: number;
  last_order_id?: number | null;
  last_order_name?: string | null;
  last_order_date?: string | null;
  birthday?: string | null;
  gender?: 0 | 1 | 2 | null;
  group_name?: string | null;
  multipass_identifier?: string | boolean | null;
  send_email_invite?: boolean;
  send_email_welcome?: boolean;
  password?: string;
  password_confirmation?: string;
  created_at?: string;
  updated_at?: string;
}

export interface HaravanCustomerListResponse {
  customers: HaravanCustomer[];
}

export interface HaravanCustomerResponse {
  customer: HaravanCustomer;
}
