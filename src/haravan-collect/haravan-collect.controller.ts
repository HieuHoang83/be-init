import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  CountHaravanCollectsQuery,
  GetHaravanCollectQuery,
  HaravanCollectBody,
  ListHaravanCollectsQuery,
} from './dto/collect.dto';
import { HaravanCollectService } from './haravan-collect.service';

/**
 * Proxy Collect Omni API (quan he san pham - nhom san pham).
 * Scope Haravan: `com.read_products`, `com.write_products`.
 *
 * GET/POST /api/v1/haravan/:orgId/collects           <-> /com/collects.json
 * GET      /api/v1/haravan/:orgId/collects/count     <-> /com/collects/count.json
 * GET/DELETE /api/v1/haravan/:orgId/collects/{id}    <-> /com/collects/{id}.json
 */
@ApiTags('Haravan Collects')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/collects')
export class HaravanCollectController {
  constructor(private readonly haravan: HaravanCollectService) {}

  @Get()
  @ApiOperation({ summary: 'Danh sach collect (GET /com/collects.json)' })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanCollectsQuery,
  ) {
    return this.haravan.listCollects(orgId, query);
  }

  @Get('count')
  @ApiOperation({ summary: 'Dem collect (GET /com/collects/count.json)' })
  count(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: CountHaravanCollectsQuery,
  ) {
    return this.haravan.countCollects(orgId, query);
  }

  @Get(':collectId')
  @ApiOperation({ summary: 'Chi tiet collect (GET /com/collects/{id}.json)' })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('collectId', ParseIntPipe) collectId: number,
    @Query() query: GetHaravanCollectQuery,
  ) {
    return this.haravan.getCollect(orgId, collectId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Gan san pham vao nhom (POST /com/collects.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanCollectBody,
  ) {
    return this.haravan.createCollect(orgId, body);
  }

  @Delete(':collectId')
  @ApiOperation({
    summary: 'Bo gan khoi nhom (DELETE /com/collects/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('collectId', ParseIntPipe) collectId: number,
  ) {
    return this.haravan.deleteCollect(orgId, collectId);
  }
}
