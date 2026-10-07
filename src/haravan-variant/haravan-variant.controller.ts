import {
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Put,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { GetHaravanVariantQuery, HaravanVariantBody } from './dto/variant.dto';
import { HaravanOmniService } from '../api/haravan-omni.service';

/**
 * Proxy Product Variant Omni API (route không nằm dưới /products).
 * Scope Haravan: `com.read_products`, `com.write_products`.
 *
 * GET/PUT /api/v1/haravan/:orgId/variants/{variantId}  ↔  /com/variants/{id}.json
 */
@ApiTags('Haravan Variants')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/variants')
export class HaravanVariantController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get(':variantId')
  @ApiOperation({
    summary: 'Chi tiet variant (GET /com/variants/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('variantId', ParseIntPipe) variantId: number,
    @Query() query: GetHaravanVariantQuery,
  ) {
    return this.haravan.getVariant(orgId, variantId, query);
  }

  @Put(':variantId')
  @ApiOperation({
    summary: 'Cap nhat variant (PUT /com/variants/{id}.json)',
  })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('variantId', ParseIntPipe) variantId: number,
    @Body() body: HaravanVariantBody,
  ) {
    return this.haravan.updateProductVariant(orgId, variantId, {
      variant: { id: variantId, ...body.variant },
    });
  }
}
