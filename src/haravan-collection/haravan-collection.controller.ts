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
  CountHaravanCollectionsQuery,
  GetHaravanCollectionQuery,
  HaravanCollectionBody,
  ListHaravanCollectionsQuery,
} from './dto/collection.dto';
import { HaravanOmniService } from '../api/haravan-omni.service';

/**
 * Proxy Custom Collection Omni API (nhom san pham tuy chinh).
 * Scope Haravan: `com.read_products`, `com.write_products`.
 *
 * GET/POST   /api/v1/haravan/:orgId/custom_collections             <-> /com/custom_collections.json
 * GET        /api/v1/haravan/:orgId/custom_collections/count       <-> /com/custom_collections/count.json
 * GET/PUT/DELETE /api/v1/haravan/:orgId/custom_collections/{id}    <-> /com/custom_collections/{id}.json
 */
@ApiTags('Haravan Custom Collections')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/custom_collections')
export class HaravanCollectionController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get()
  @ApiOperation({
    summary: 'Danh sach nhom (GET /com/custom_collections.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanCollectionsQuery,
  ) {
    return this.haravan.listCollections(orgId, query);
  }

  @Get('count')
  @ApiOperation({
    summary: 'Dem nhom (GET /com/custom_collections/count.json)',
  })
  count(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: CountHaravanCollectionsQuery,
  ) {
    return this.haravan.countCollections(orgId, query);
  }

  @Get(':collectionId')
  @ApiOperation({
    summary: 'Chi tiet nhom (GET /com/custom_collections/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('collectionId', ParseIntPipe) collectionId: number,
    @Query() query: GetHaravanCollectionQuery,
  ) {
    return this.haravan.getCollection(orgId, collectionId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Tao nhom (POST /com/custom_collections.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanCollectionBody,
  ) {
    return this.haravan.createCollection(orgId, body);
  }

  @Put(':collectionId')
  @ApiOperation({
    summary: 'Cap nhat nhom (PUT /com/custom_collections/{id}.json)',
  })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('collectionId', ParseIntPipe) collectionId: number,
    @Body() body: HaravanCollectionBody,
  ) {
    return this.haravan.updateCollection(orgId, collectionId, {
      collection: { id: collectionId, ...body.collection },
    });
  }

  @Delete(':collectionId')
  @ApiOperation({
    summary: 'Xoa nhom (DELETE /com/custom_collections/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('collectionId', ParseIntPipe) collectionId: number,
  ) {
    return this.haravan.deleteCollection(orgId, collectionId);
  }
}
