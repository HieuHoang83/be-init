import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CustomerListQuery, CustomerService } from './customer.service';

/**
 * API khach hang.
 *
 * `JwtAuthGuard` da la guard global nen khong `@UseGuards` o tung route -
 * xem `app.module.ts`. Chi route danh dau `@Public()` moi bo qua.
 *
 * Ket noi: app webhook -> `OrderService` luu don + khach -> bang `customers`.
 */
@ApiTags('customers')
@ApiBearerAuth()
@Controller({ path: 'customers', version: '1' })
export class CustomerController {
  constructor(private readonly customerService: CustomerService) {}

  /**
   * So luong khach trong he thong.
   *
   *   GET /api/v1/customers/stats
   *   GET /api/v1/customers/stats?orgId=200001220496
   *
   * `total` la so KHACH, khong phai so don: mot khach nhieu don chi dem 1.
   */
  @Get('stats')
  @ApiOperation({ summary: 'Thong ke so luong khach hang' })
  getStats(@Query('orgId') orgId?: string) {
    return this.customerService.getStats(orgId ? Number(orgId) : undefined);
  }

  /**
   * Danh sach khach, co phan trang + tim theo ten/sdt.
   *
   *   GET /api/v1/customers?search=0961277633&kind=returning&page=1&limit=20
   */
  @Get()
  @ApiOperation({ summary: 'Danh sach khach hang' })
  findAll(
    @Query()
    query: CustomerListQuery & {
      orgId?: string;
      page?: string;
      limit?: string;
      search?: string;
    },
  ) {
    return this.customerService.findAll({
      ...query,
      orgId: query.orgId ? Number(query.orgId) : undefined,
      page: query.page ? Number(query.page) : undefined,
      limit: query.limit ? Number(query.limit) : undefined,
    });
  }

  /**
   * Chi tiet khach + cac don cua khach do.
   *
   *   GET /api/v1/customers/200001220496/0961277633
   *
   * `key` nhan sdt, email, hoac `haravanCustomerId` deu duoc.
   */
  @Get(':orgId/:key')
  @ApiOperation({ summary: 'Chi tiet khach hang va cac don' })
  async findOne(@Param('orgId') orgId: string, @Param('key') key: string) {
    const result = await this.customerService.findOneWithOrders(
      Number(orgId),
      key,
    );
    if (!result)
      return { found: false, message: `Khong tim thay khach "${key}"` };

    return {
      found: true,
      customer: result.customer,
      orders: result.orders,
      /** Da mua >= 2 don hay chua */
      isReturning: (result.customer.haravanOrdersCount ?? 0) >= 2,
    };
  }
}
