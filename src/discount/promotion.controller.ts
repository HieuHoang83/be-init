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
  GetHaravanPromotionQuery,
  HaravanPromotionBody,
  ListHaravanPromotionsQuery,
} from './dto/promotion.dto';

/**
 * Proxy Promotion Omni API (khuyen mai).
 * Scope Haravan: `com.read_discounts`, `com.write_discounts` (private app).
 *
 * GET/POST  /api/v1/haravan/:orgId/promotions               <-> /com/promotions.json
 * GET       /api/v1/haravan/:orgId/promotions/{id}          <-> /com/promotions/{id}.json
 * PUT       /api/v1/haravan/:orgId/promotions/{id}/enable   <-> /com/discounts/{id}/enable.json
 * PUT       /api/v1/haravan/:orgId/promotions/{id}/disable  <-> /com/discounts/{id}/disable.json
 * DELETE    /api/v1/haravan/:orgId/promotions/{id}          <-> /com/promotions/{id}.json
 */
@ApiTags('Haravan Promotions')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/promotions')
export class PromotionController {
  constructor(private readonly discounts: DiscountService) {}

  @Get()
  @ApiOperation({ summary: 'Danh sach khuyen mai (GET /com/promotions.json)' })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanPromotionsQuery,
  ) {
    return this.discounts.listPromotions(orgId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Tao khuyen mai (POST /com/promotions.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanPromotionBody,
  ) {
    return this.discounts.createPromotion(orgId, body);
  }

  @Get(':promotionId')
  @ApiOperation({
    summary: 'Chi tiet khuyen mai (GET /com/promotions/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('promotionId', ParseIntPipe) promotionId: number,
    @Query() query: GetHaravanPromotionQuery,
  ) {
    return this.discounts.getPromotion(orgId, promotionId, query);
  }

  @Put(':promotionId/enable')
  @ApiOperation({
    summary: 'Bat khuyen mai (PUT /com/discounts/{id}/enable.json)',
  })
  enable(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('promotionId', ParseIntPipe) promotionId: number,
  ) {
    return this.discounts.enable(orgId, promotionId);
  }

  @Put(':promotionId/disable')
  @ApiOperation({
    summary: 'Tat khuyen mai (PUT /com/discounts/{id}/disable.json)',
  })
  disable(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('promotionId', ParseIntPipe) promotionId: number,
  ) {
    return this.discounts.disable(orgId, promotionId);
  }

  @Delete(':promotionId')
  @ApiOperation({
    summary: 'Xoa khuyen mai (DELETE /com/promotions/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('promotionId', ParseIntPipe) promotionId: number,
  ) {
    return this.discounts.removePromotion(orgId, promotionId);
  }
}
