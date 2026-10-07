import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/collects.json theo tài liệu Haravan Collect. */
export class ListHaravanCollectsQuery {
  @IsOptional()
  @IsString()
  ids?: string;

  /** Loc theo custom collection. */
  @IsOptional()
  @IsString()
  collection_id?: string;

  /** Loc theo san pham. */
  @IsOptional()
  @IsString()
  product_id?: string;

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

/** Query GET /com/collects/count.json. */
export class CountHaravanCollectsQuery {
  @IsOptional()
  @IsString()
  collection_id?: string;

  @IsOptional()
  @IsString()
  product_id?: string;
}

/** Query GET /com/collects/{id}.json. */
export class GetHaravanCollectQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

/** Body POST /com/collects.json. */
export class HaravanCollectBody {
  @Allow()
  @IsObject()
  collect!: Record<string, unknown>;
}
