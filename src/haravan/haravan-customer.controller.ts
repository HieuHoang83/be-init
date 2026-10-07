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
  GetHaravanCustomerQuery,
  HaravanCustomerBody,
  HaravanTagsBody,
  ListHaravanCustomersQuery,
  SearchHaravanCustomersQuery,
} from './dto/customer.dto';
import { HaravanOmniService } from './haravan.service';

/**
 * Proxy Customer Omni API.
 * Scope Haravan: `com.read_customers`, `com.write_customers`.
 *
 * Khác `/api/v1/customers` (dữ liệu đã lưu Mongo từ webhook đơn hàng).
 */
@ApiTags('Haravan Customers')
@ApiBearerAuth('token')
@Controller('haravan/:orgId/customers')
export class HaravanCustomerController {
  constructor(private readonly haravan: HaravanOmniService) {}

  @Get()
  @ApiOperation({
    summary: 'Danh sach khach hang shop (GET /com/customers.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanCustomersQuery,
  ) {
    return this.haravan.listCustomers(orgId, query);
  }

  @Get('search')
  @ApiOperation({
    summary: 'Tim khach hang (GET /com/customers/search.json)',
  })
  search(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: SearchHaravanCustomersQuery,
  ) {
    return this.haravan.searchCustomers(orgId, query);
  }

  @Get('count')
  @ApiOperation({
    summary: 'Dem khach hang (GET /com/customers/count.json)',
  })
  count(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanCustomersQuery,
  ) {
    return this.haravan.countCustomers(orgId, query);
  }

  @Get(':customerId')
  @ApiOperation({
    summary: 'Chi tiet khach hang (GET /com/customers/{id}.json)',
  })
  getOne(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Query() query: GetHaravanCustomerQuery,
  ) {
    return this.haravan.getCustomer(orgId, customerId, query);
  }

  @Post()
  @ApiOperation({ summary: 'Tao khach hang (POST /com/customers.json)' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanCustomerBody,
  ) {
    return this.haravan.createCustomer(orgId, body);
  }

  @Put(':customerId')
  @ApiOperation({
    summary: 'Cap nhat khach hang (PUT /com/customers/{id}.json)',
  })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Body() body: HaravanCustomerBody,
  ) {
    return this.haravan.updateCustomer(orgId, customerId, {
      customer: { id: customerId, ...body.customer },
    });
  }

  @Delete(':customerId')
  @ApiOperation({
    summary: 'Xoa khach hang (DELETE /com/customers/{id}.json)',
  })
  remove(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
  ) {
    return this.haravan.deleteCustomer(orgId, customerId);
  }

  @Post(':customerId/tags')
  @ApiOperation({
    summary: 'Them tag (POST /com/customers/{id}/tags.json)',
  })
  addTags(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Body() body: HaravanTagsBody,
  ) {
    return this.haravan.addCustomerTags(orgId, customerId, body);
  }

  @Delete(':customerId/tags')
  @ApiOperation({
    summary: 'Xoa tag (DELETE /com/customers/{id}/tags.json)',
  })
  removeTags(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) customerId: number,
    @Body() body: HaravanTagsBody,
  ) {
    return this.haravan.removeCustomerTags(orgId, customerId, body);
  }
}
