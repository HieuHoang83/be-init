import { Allow, IsObject, IsOptional, IsString } from 'class-validator';

/** Query GET /com/customers.json theo tài liệu Haravan Customer. */
export class ListHaravanCustomersQuery {
  @IsOptional()
  @IsString()
  ids?: string;

  @IsOptional()
  @IsString()
  since_id?: string;

  @IsOptional()
  @IsString()
  limit?: string;

  @IsOptional()
  @IsString()
  page?: string;

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
  fields?: string;

  @IsOptional()
  @IsString()
  order?: string;
}

export class SearchHaravanCustomersQuery {
  @IsOptional()
  @IsString()
  query?: string;

  @IsOptional()
  @IsString()
  order?: string;

  @IsOptional()
  @IsString()
  created_at_min?: string;

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

export class GetHaravanCustomerQuery {
  @IsOptional()
  @IsString()
  fields?: string;
}

export class HaravanCustomerBody {
  @Allow()
  @IsObject()
  customer!: Record<string, unknown>;
}

export class HaravanTagsBody {
  @IsString()
  tags!: string;
}
