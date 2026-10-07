import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/products/{id}/variants.json theo tài liệu Haravan Product Variant. */
export class ListHaravanVariantsQuery {
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
  fields?: string;
}

export class CountHaravanVariantsQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

export class GetHaravanVariantQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

export class HaravanVariantBody {
  @Allow()
  @IsObject()
  variant!: Record<string, unknown>;
}
