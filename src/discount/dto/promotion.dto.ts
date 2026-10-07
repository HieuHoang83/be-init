import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/promotions.json theo tài liệu Haravan Promotion. */
export class ListHaravanPromotionsQuery {
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
  code?: string;

  @IsOptional()
  @IsString()
  fields?: string;
}

/** Query GET /com/promotions/{id}.json. */
export class GetHaravanPromotionQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

/** Body POST /com/promotions.json. */
export class HaravanPromotionBody {
  @Allow()
  @IsObject()
  promotion!: Record<string, unknown>;
}
