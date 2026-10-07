import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { DiscountService } from './discount.service';
import {
  GetHaravanDiscountQuery,
  HaravanDiscountBody,
  ListHaravanDiscountsQuery,
} from './dto/discount.dto';

/**
 * Proxy DiscountCode Omni API (ma giam gia).
 * Scope Haravan: `com.read_discounts`, `com.write_discounts` (private app).
 *
 * GET/POST  /api/v1/haravan/:orgId/discounts              <-> /com/discounts.json
 * GET       /api/v1/haravan/:orgId/discounts/{id}         <-> /com/discounts/{id}.json
 * PUT       /api/v1/haravan/:orgId/discounts/{id}/enable  <-> /com/discounts/{id}/enable.json
 * PUT       /api/v1/haravan/:orgId/discounts/{id}/disable <-> /com/discounts/{id}/disable.json
 * DELETE    /api/v1/haravan/:orgId/discounts/{id}         <-> /com/discounts/{id}.json
 */
@ApiTags('Haravan Discounts')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/discounts')
export class DiscountController {
  constructor(private readonly discounts: DiscountService) {}

  @Get()
  @ApiOperation({
    summary: 'Danh sach ma giam gia dang bat (GET /com/discounts.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanDiscountsQuery,
  ) {
    return this.discounts.list(orgId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Tao ma giam gia (POST /com/discounts.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanDiscountBody,
  ) {
    return this.discounts.create(orgId, body);
  }

  @Get(':discountId')
  @ApiOperation({
    summary: 'Chi tiet ma giam gia (GET /com/discounts/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('discountId', ParseIntPipe) discountId: number,
    @Query() query: GetHaravanDiscountQuery,
  ) {
    return this.discounts.getOne(orgId, discountId, query);
  }

  @Put(':discountId/enable')
  @ApiOperation({
    summary: 'Bat ma giam gia (PUT /com/discounts/{id}/enable.json)',
  })
  enable(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('discountId', ParseIntPipe) discountId: number,
  ) {
    return this.discounts.enable(orgId, discountId);
  }

  @Put(':discountId/disable')
  @ApiOperation({
    summary: 'Tat ma giam gia (PUT /com/discounts/{id}/disable.json)',
  })
  disable(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('discountId', ParseIntPipe) discountId: number,
  ) {
    return this.discounts.disable(orgId, discountId);
  }

  @Delete(':discountId')
  @ApiOperation({
    summary: 'Xoa ma giam gia (DELETE /com/discounts/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('discountId', ParseIntPipe) discountId: number,
  ) {
    return this.discounts.remove(orgId, discountId);
  }
}
