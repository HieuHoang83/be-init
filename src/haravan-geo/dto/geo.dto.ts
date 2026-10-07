import { IsOptional, IsString } from 'class-validator';

/** Query chung cho danh muc dia ly Haravan (countries/provinces/districts/wards). */
export class ListHaravanGeoQuery {
  @IsOptional()
  @IsString()
  page?: string;

  @IsOptional()
  @IsString()
  limit?: string;

  @IsOptional()
  @IsString()
  fields?: string;
}
