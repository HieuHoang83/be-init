import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/products.json theo tài liệu Haravan Product. */
export class ListHaravanProductsQuery {
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
  since_id?: string;

  @IsOptional()
  @IsString()
  vendor?: string;

  @IsOptional()
  @IsString()
  handle?: string;

  @IsOptional()
  @IsString()
  product_type?: string;

  @IsOptional()
  @IsString()
  collection_id?: string;

  @IsOptional()
  @IsString()
  sku?: string;

  @IsOptional()
  @IsString()
  barcode?: string;

  @IsOptional()
  @IsString()
  created_at_min?: string;

  @IsOptional()
  @IsString()
  created_at_max?: string;

  @IsOptional()
  @IsString()
  updated_at_min?: string;

  @IsOptional()
  @IsString()
  updated_at_max?: string;

  @IsOptional()
  @IsString()
  published_at_min?: string;

  @IsOptional()
  @IsString()
  published_at_max?: string;

  @IsOptional()
  @IsString()
  fields?: string;
}

export class CountHaravanProductsQuery {
  @IsOptional()
  @IsString()
  vendor?: string;

  @IsOptional()
  @IsString()
  product_type?: string;

  @IsOptional()
  @IsString()
  collection_id?: string;

  @IsOptional()
  @IsString()
  created_at_min?: string;

  @IsOptional()
  @IsString()
  created_at_max?: string;

  @IsOptional()
  @IsString()
  updated_at_min?: string;

  @IsOptional()
  @IsString()
  updated_at_max?: string;

  @IsOptional()
  @IsString()
  published_at_min?: string;

  @IsOptional()
  @IsString()
  published_at_max?: string;
}

export class GetHaravanProductQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

export class HaravanProductBody {
  @Allow()
  @IsObject()
  product!: Record<string, unknown>;
}

export class HaravanTagsBody {
  @IsString()
  tags!: string;
}
