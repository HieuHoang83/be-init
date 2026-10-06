import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CustomerListQuery, CustomerService } from './customer.service';

/**
 * API quản lý khách hàng.
 *
 * `JwtAuthGuard` đã được áp dụng toàn cục nên không cần thêm `@UseGuards`
 * cho từng tuyến. Chỉ tuyến có `@Public()` mới được bỏ qua xác thực.
 *
 * Webhook ứng dụng gọi `OrderService` để lưu đơn hàng và thông tin khách.
 */
@ApiTags('customers')
@ApiBearerAuth()
@Controller({ path: 'customers', version: '1' })
export class CustomerController {
  constructor(private readonly customerService: CustomerService) {}

  /**
   * Lấy số lượng khách trong hệ thống.
   *
   *   GET /api/v1/customers/stats
   *   GET /api/v1/customers/stats?orgId=200001220496
   *
   * `total` là số khách, không phải số đơn; mỗi khách chỉ được tính một lần.
   */
  @Get('stats')
  @ApiOperation({ summary: 'Thong ke so luong khach hang' })
  getStats(@Query('orgId') orgId?: string) {
    return this.customerService.getStats(orgId ? Number(orgId) : undefined);
  }

  /**
   * Lấy danh sách khách có phân trang và tìm theo tên hoặc số điện thoại.
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
   * Lấy thông tin khách hàng và các đơn hàng của khách đó.
   *
   *   GET /api/v1/customers/200001220496/0961277633
   *
   * `key` có thể là số điện thoại, email hoặc `haravanCustomerId`.
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
      /** Khách đã mua ít nhất hai đơn hay chưa. */
      isReturning: (result.customer.haravanOrdersCount ?? 0) >= 2,
    };
  }
}
