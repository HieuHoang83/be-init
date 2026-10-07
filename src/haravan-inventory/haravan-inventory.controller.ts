import {
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  HaravanInventoryAdjustBody,
  ListHaravanInventoryLocationsQuery,
} from '../haravan-location/dto/location.dto';
import { HaravanOmniService } from '../api/haravan-omni.service';

/**
 * Proxy Inventory Omni API (ton kho theo kho cua variant).
 * Scope Haravan: `com.read_products`, `com.write_products`.
 *
 * GET  /api/v1/haravan/:orgId/inventory_locations            <-> /com/inventory_locations.json
 * POST /api/v1/haravan/:orgId/inventories/adjustorset        <-> /com/inventories/adjustorset.json
 */
@ApiTags('Haravan Inventory')
@ApiBearerAuth('token')
@Controller('haravan/:orgId')
export class HaravanInventoryController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get('inventory_locations')
  @ApiOperation({
    summary: 'Ton kho theo kho (GET /com/inventory_locations.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanInventoryLocationsQuery,
  ) {
    return this.haravan.listInventoryLocations(orgId, query);
  }

  @Post('inventories/adjustorset')
  @ApiOperation({
    summary: 'Chinh sua ton kho (POST /com/inventories/adjustorset.json)',
  })
  adjust(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanInventoryAdjustBody,
  ) {
    return this.haravan.adjustInventory(orgId, body);
  }
}
