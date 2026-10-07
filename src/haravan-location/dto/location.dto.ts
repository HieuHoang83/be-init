import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/locations.json theo tài liệu Haravan Location. */
export class ListHaravanLocationsQuery {
  @IsOptional()
  @IsString()
  ids?: string;

  @IsOptional()
  @IsString()
  limit?: string;

  @IsOptional()
  @IsString()
  page?: string;

  @IsOptional()
  @IsString()
  fields?: string;
}

/** Query GET /com/inventory_locations.json theo tài liệu Haravan Inventory. */
export class ListHaravanInventoryLocationsQuery {
  /** Danh sach location_id, ngan cach dau phay. Toi da 50 id moi goi. */
  @IsOptional()
  @IsString()
  location_ids?: string;

  /** Danh sach variant_id, ngan cach dau phay. Toi da 50 id moi goi. */
  @IsOptional()
  @IsString()
  variant_ids?: string;

  @IsOptional()
  @IsString()
  product_ids?: string;

  @IsOptional()
  @IsString()
  limit?: string;

  @IsOptional()
  @IsString()
  page?: string;

  @IsOptional()
  @IsString()
  fields?: string;
}

/** Body POST /com/inventories/adjustorset.json. */
export class HaravanInventoryAdjustBody {
  @Allow()
  @IsObject()
  inventory!: Record<string, unknown>;
}
