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
  GetHaravanCustomerAddressQuery,
  HaravanCustomerAddressBody,
  ListHaravanCustomerAddressesQuery,
} from './dto/customer.dto';
import { HaravanOmniService } from '../api/haravan-omni.service';

/**
 * Proxy CustomerAddress Omni API (dia chi khach hang).
 * Scope Haravan: `com.read_customers`, `com.write_customers`.
 *
 * GET/POST   /api/v1/haravan/:orgId/customers/:customerId/addresses
 *              <-> /com/customers/{id}/addresses.json
 * GET/PUT/DELETE .../addresses/:addressId
 *              <-> /com/customers/{id}/addresses/{addressId}.json
 * PUT        .../addresses/set            <-> /com/customers/{id}/addresses/set.json
 * PUT        .../addresses/:addressId/default
 *              <-> /com/customers/{id}/addresses/{addressId}/default.json
 */
@ApiTags('Haravan Customer Addresses')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/customers/:customerId/addresses')
export class HaravanCustomerAddressController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get()
  @ApiOperation({
    summary: 'Danh sach dia chi (GET /com/customers/{id}/addresses.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Query() query: ListHaravanCustomerAddressesQuery,
  ) {
    return this.haravan.listCustomerAddresses(orgId, customerId, query);
  }

  @Put('set')
  @ApiOperation({
    summary:
      'Thao tac nhieu dia chi (PUT /com/customers/{id}/addresses/set.json)',
  })
  setMany(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Body() body: Record<string, unknown>,
  ) {
    return this.haravan.setCustomerAddresses(orgId, customerId, body);
  }

  @Get(':addressId')
  @ApiOperation({
    summary:
      'Chi tiet dia chi (GET /com/customers/{id}/addresses/{addressId}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Param('addressId', ParseIntPipe) addressId: number,
    @Query() query: GetHaravanCustomerAddressQuery,
  ) {
    return this.haravan.getCustomerAddress(orgId, customerId, addressId, query);
  }

  @Post()
  @ApiOperation({
    summary: 'Tao dia chi (POST /com/customers/{id}/addresses.json)',
  })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Body() body: HaravanCustomerAddressBody,
  ) {
    return this.haravan.createCustomerAddress(orgId, customerId, body);
  }

  @Put(':addressId/default')
  @ApiOperation({
    summary:
      'Dat dia chi mac dinh (PUT /com/customers/{id}/addresses/{addressId}/default.json)',
  })
  setDefault(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Param('addressId', ParseIntPipe) addressId: number,
  ) {
    return this.haravan.setCustomerAddressDefault(orgId, customerId, addressId);
  }

  @Put(':addressId')
  @ApiOperation({
    summary:
      'Cap nhat dia chi (PUT /com/customers/{id}/addresses/{addressId}.json)',
  })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Param('addressId', ParseIntPipe) addressId: number,
    @Body() body: HaravanCustomerAddressBody,
  ) {
    return this.haravan.updateCustomerAddress(orgId, customerId, addressId, {
      address: { id: addressId, ...body.address },
    });
  }

  @Delete(':addressId')
  @ApiOperation({
    summary:
      'Xoa dia chi (DELETE /com/customers/{id}/addresses/{addressId}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Param('addressId', ParseIntPipe) addressId: number,
  ) {
    return this.haravan.deleteCustomerAddress(orgId, customerId, addressId);
  }
}
