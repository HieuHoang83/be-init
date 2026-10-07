import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/discounts.json theo tài liệu Haravan DiscountCode. */
export class ListHaravanDiscountsQuery {
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

/** Query GET /com/discounts/{id}.json. */
export class GetHaravanDiscountQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

/** Body POST /com/discounts.json. */
export class HaravanDiscountBody {
  @Allow()
  @IsObject()
  discount!: Record<string, unknown>;
}
