import { Controller, Get, Param, ParseIntPipe, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { ListHaravanGeoQuery } from './dto/geo.dto';
import { HaravanGeoService } from './haravan-geo.service';

/**
 * Proxy danh muc dia ly Haravan (quoc gia / tinh / quan / phuong).
 * Scope Haravan: `com.read_shop`.
 *
 * GET .../countries                            <-> /com/countries.json
 * GET .../countries/:countryId/provinces       <-> /com/countries/{id}/provinces.json
 * GET .../provinces/:provinceId/districts      <-> /com/provinces/{id}/districts.json
 * GET .../districts/:districtId/wards          <-> /com/districts/{id}/wards.json
 *
 * Dung cho form dia chi khach hang chon tinh -> quan -> phuong dong bo voi Haravan.
 */
@ApiTags('Haravan Geo')
@ApiBearerAuth('token')
@Controller('haravan/:orgId')
export class HaravanGeoController {
  constructor(private readonly haravan: HaravanGeoService) {}

  @Get('countries')
  @ApiOperation({ summary: 'Danh sach quoc gia (GET /com/countries.json)' })
  listCountries(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanGeoQuery,
  ) {
    return this.haravan.listCountries(orgId, query);
  }

  @Get('countries/:countryId/provinces')
  @ApiOperation({
    summary:
      'Danh sach tinh/thanh pho (GET /com/countries/{id}/provinces.json)',
  })
  listProvinces(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('countryId', ParseIntPipe) countryId: number,
    @Query() query: ListHaravanGeoQuery,
  ) {
    return this.haravan.listProvinces(orgId, countryId, query);
  }

  @Get('provinces/:provinceId/districts')
  @ApiOperation({
    summary: 'Danh sach quan/huyen (GET /com/provinces/{id}/districts.json)',
  })
  listDistricts(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('provinceId', ParseIntPipe) provinceId: number,
    @Query() query: ListHaravanGeoQuery,
  ) {
    return this.haravan.listDistricts(orgId, provinceId, query);
  }

  @Get('districts/:districtId/wards')
  @ApiOperation({
    summary: 'Danh sach phuong/xa (GET /com/districts/{id}/wards.json)',
  })
  listWards(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('districtId', ParseIntPipe) districtId: number,
    @Query() query: ListHaravanGeoQuery,
  ) {
    return this.haravan.listWards(orgId, districtId, query);
  }
}
