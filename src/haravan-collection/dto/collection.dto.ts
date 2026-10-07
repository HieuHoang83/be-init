import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/custom_collections.json theo tài liệu Haravan Custom Collection. */
export class ListHaravanCollectionsQuery {
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
  title?: string;

  @IsOptional()
  @IsString()
  handle?: string;

  @IsOptional()
  @IsString()
  fields?: string;

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
}

/** Query GET /com/custom_collections/count.json. */
export class CountHaravanCollectionsQuery {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  handle?: string;

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
}

/** Query GET /com/custom_collections/{id}.json. */
export class GetHaravanCollectionQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

/** Body POST/PUT /com/custom_collections.json. */
export class HaravanCollectionBody {
  @Allow()
  @IsObject()
  collection!: Record<string, unknown>;
}
