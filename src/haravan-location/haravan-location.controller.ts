import { Controller, Get, Param, ParseIntPipe, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ListHaravanLocationsQuery } from './dto/location.dto';
import { HaravanOmniService } from '../api/haravan-omni.service';

/**
 * Proxy Location Omni API.
 * Scope Haravan: `com.read_locations` (hoac `com.read_shop`).
 *
 * GET /api/v1/haravan/:orgId/locations  <->  /com/locations.json
 */
@ApiTags('Haravan Locations')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/locations')
export class HaravanLocationController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get()
  @ApiOperation({ summary: 'Danh sach kho (GET /com/locations.json)' })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanLocationsQuery,
  ) {
    return this.haravan.listLocations(orgId, query);
  }

  @Get(':locationId')
  @ApiOperation({ summary: 'Chi tiet kho (GET /com/locations/{id}.json)' })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('locationId', ParseIntPipe) locationId: number,
    @Query() query: ListHaravanLocationsQuery,
  ) {
    return this.haravan.getLocation(orgId, locationId, query);
  }
}
