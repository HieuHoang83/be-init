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
import {
  CountHaravanProductsQuery,
  GetHaravanProductQuery,
  HaravanProductBody,
  HaravanTagsBody,
  ListHaravanProductsQuery,
} from './dto/product.dto';
import {
  CountHaravanVariantsQuery,
  HaravanVariantBody,
  ListHaravanVariantsQuery,
} from './dto/variant.dto';
import { HaravanOmniService } from './haravan.service';

/**
 * Proxy Product Omni API.
 * Scope Haravan: `com.read_products`, `com.write_products`.
 *
 * GET/POST /api/v1/haravan/:orgId/products  ↔  /com/products.json
 */
@ApiTags('Haravan Products')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/products')
export class HaravanProductController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get()
  @ApiOperation({ summary: 'Danh sach san pham (GET /com/products.json)' })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanProductsQuery,
  ) {
    return this.haravan.listProducts(orgId, query);
  }

  @Get('count')
  @ApiOperation({ summary: 'Dem san pham (GET /com/products/count.json)' })
  count(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: CountHaravanProductsQuery,
  ) {
    return this.haravan.countProducts(orgId, query);
  }

  @Get(':productId')
  @ApiOperation({
    summary: 'Chi tiet san pham (GET /com/products/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Query() query: GetHaravanProductQuery,
  ) {
    return this.haravan.getProduct(orgId, productId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Tao san pham (POST /com/products.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanProductBody,
  ) {
    return this.haravan.createProduct(orgId, body);
  }

  @Put(':productId')
  @ApiOperation({
    summary: 'Cap nhat san pham (PUT /com/products/{id}.json)',
  })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Body() body: HaravanProductBody,
  ) {
    return this.haravan.updateProduct(orgId, productId, {
      product: { id: productId, ...body.product },
    });
  }

  @Delete(':productId')
  @ApiOperation({
    summary: 'Xoa san pham (DELETE /com/products/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
  ) {
    return this.haravan.deleteProduct(orgId, productId);
  }

  @Get(':productId/variants')
  @ApiOperation({
    summary: 'Danh sach variant (GET /com/products/{id}/variants.json)',
  })
  listVariants(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Query() query: ListHaravanVariantsQuery,
  ) {
    return this.haravan.listProductVariants(orgId, productId, query);
  }

  @Get(':productId/variants/count')
  @ApiOperation({
    summary: 'Dem variant (GET /com/products/{id}/variants/count.json)',
  })
  countVariants(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Query() query: CountHaravanVariantsQuery,
  ) {
    return this.haravan.countProductVariants(orgId, productId, query);
  }

  @Post(':productId/variants')
  @ApiOperation({
    summary: 'Tao variant (POST /com/products/{id}/variants.json)',
  })
  createVariant(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Body() body: HaravanVariantBody,
  ) {
    return this.haravan.createProductVariant(orgId, productId, body);
  }

  @Delete(':productId/variants/:variantId')
  @ApiOperation({
    summary:
      'Xoa variant (DELETE /com/products/{id}/variants/{variantId}.json)',
  })
  removeVariant(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Param('variantId', ParseIntPipe) variantId: number,
  ) {
    return this.haravan.deleteProductVariant(orgId, productId, variantId);
  }

  @Post(':productId/tags')
  @ApiOperation({
    summary: 'Them tag (POST /com/products/{id}/tags.json)',
  })
  addTags(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Body() body: HaravanTagsBody,
  ) {
    return this.haravan.addProductTags(orgId, productId, body);
  }

  @Delete(':productId/tags')
  @ApiOperation({
    summary: 'Xoa tag (DELETE /com/products/{id}/tags.json)',
  })
  removeTags(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('productId', ParseIntPipe) productId: number,
    @Body() body: HaravanTagsBody,
  ) {
    return this.haravan.removeProductTags(orgId, productId, body);
  }
}
