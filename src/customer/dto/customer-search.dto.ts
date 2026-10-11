import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

/**
 * Tham so tra ve cho `GET /api/v1/customers/search`.
 *
 * Cac truong so giu dang chuoi vi `ValidationPipe` chung cua ung dung khong bat `transform`;
 * controller chuyen sang so truoc khi xu ly.
 */
export class CustomerSearchDto {
  /** Shop can tim; bat buoc vi du lieu duoc chia theo tung org. */
  @IsString()
  orgId!: string;

  /**
   * Chuoi tim kiem.
   *
 * - `633` — ba so cuoi cua so dien thoai (truong hop chinh)
   * - `633, 888` — nhieu nhom ba so cuoi, ket qua la hop lai
   * - `0961277633` — so dien thoai day du
   * - `Nguyen Van A` — tim theo ten hoac email
   */
  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @IsString()
  page?: string;

  @IsOptional()
  @IsString()
  limit?: string;

  @IsOptional()
  @IsIn(['returning', 'first_time', 'all'])
  kind?: string;

  @IsOptional()
  @IsIn(['newest', 'lastSeen', 'spent', 'orders'])
  sort?: string;
}

/** Tham so cho lenh nap lai toan bo khach tu Mongo sang Elasticsearch. */
export class CustomerReindexDto {
  @ApiPropertyOptional({ default: 500, minimum: 50, maximum: 2000 })
  @IsOptional()
  @IsInt()
  @Min(50)
  @Max(2000)
  batchSize?: number;
}
