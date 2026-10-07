/** Ảnh sản phẩm theo tài liệu Haravan Product Image. */
export interface HaravanProductImage {
  id?: number;
  product_id?: number;
  position?: number;
  src?: string;
  filename?: string;
  variant_ids?: number[];
  created_at?: string;
  updated_at?: string;
}

/** Tồn kho nâng cao trên variant. */
export interface HaravanInventoryAdvance {
  qty_available?: number;
  qty_onhand?: number;
  qty_commited?: number;
  qty_incoming?: number;
}

export interface HaravanVariantUnit {
  id?: number;
  unit?: string;
  base?: boolean;
  sellable?: boolean;
  ratio?: number;
  barcode?: string;
  sku?: string;
  price?: number;
}

export interface HaravanProductVariant {
  id?: number;
  product_id?: number;
  title?: string;
  price?: number;
  compare_at_price?: number | null;
  sku?: string;
  barcode?: string;
  grams?: number;
  inventory_quantity?: number;
  inventory_management?: string | null;
  inventory_policy?: string;
  inventory_advance?: HaravanInventoryAdvance;
  fulfillment_service?: string | null;
  requires_shipping?: boolean;
  taxable?: boolean;
  position?: number;
  image_id?: number | null;
  option1?: string | null;
  option2?: string | null;
  option3?: string | null;
  lot_support?: boolean;
  variant_units?: HaravanVariantUnit[];
  created_at?: string;
  updated_at?: string;
}

export interface HaravanProductOption {
  id?: number;
  product_id?: number;
  name?: string;
  position?: number;
}

/**
 * Product resource — scopes `com.read_products`, `com.write_products`.
 * Nguồn: https://docs.haravan.com (Omni API Product).
 */
export interface HaravanProduct {
  id?: number;
  title?: string;
  body_html?: string;
  vendor?: string;
  product_type?: string;
  handle?: string;
  tags?: string;
  template_suffix?: string | null;
  published?: boolean;
  published_at?: string | null;
  published_scope?: 'web' | 'pos' | 'global' | string;
  only_hide_from_list?: boolean;
  not_allow_promotion?: boolean;
  images?: HaravanProductImage[];
  variants?: HaravanProductVariant[];
  options?: HaravanProductOption[];
  created_at?: string;
  updated_at?: string;
}

export interface HaravanProductListResponse {
  products: HaravanProduct[];
}

export interface HaravanProductResponse {
  product: HaravanProduct;
}

export interface HaravanCountResponse {
  count: number;
}

export interface HaravanTagsResponse {
  tags: string;
}
