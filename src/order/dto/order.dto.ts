import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { FINANCIAL_STATUSES, FinancialStatus } from '../../interface/order.interface';
import { OrderStatus } from '../order.entity';
import { WebhookPrivateStatus } from '../../webhook-private/webhook-private.entity';

export class ListOrdersQuery {
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @IsString()
  email?: string;

  @IsOptional() @IsString()
  orderNumber?: string;

  @IsOptional() @IsIn(Object.values(OrderStatus))
  status?: OrderStatus;

  @IsOptional() @IsIn(FINANCIAL_STATUSES)
  financialStatus?: FinancialStatus;

  @IsOptional() @IsIn(['confirmed', 'unconfirmed'])
  confirmedStatus?: string;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  page?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100)
  limit?: number;
}

export class ListWebhookEventsQuery {
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @IsString()
  topic?: string;

  @IsOptional() @IsIn(Object.values(WebhookPrivateStatus))
  status?: WebhookPrivateStatus;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  page?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100)
  limit?: number;
}

export class ConfirmOrderBody {
  /** Nguoi thuc hien, ghi vao audit log */
  @IsOptional() @IsString()
  actor?: string;

  /** Bo qua rule khach quay lai, xac nhan tay */
  @IsOptional() @Type(() => Boolean) @IsBoolean()
  force?: boolean;
}

export class GetOrderStatsQuery {
  @IsOptional() @Type(() => Number) @IsInt()
  orgId?: number;

  @IsOptional() @Type(() => Number) @IsNumber()
  minTotalPrice?: number;
}
