import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CustomerListQuery, CustomerService } from './customer.service';
import { CustomerIndexService } from './customer-index.service';
import { CustomerSearchService } from './customer-search.service';
import { JobQueue, JOB_NAMES } from '../queue/queue.service';
import {
  CustomerReindexDto,
  CustomerSearchDto,
} from './dto/customer-search.dto';
import {
  CreateCustomerBody,
  UpdateCustomerBody,
} from './dto/customer-action.dto';

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
  constructor(
    private readonly customerService: CustomerService,
    private readonly searchService: CustomerSearchService,
    private readonly indexService: CustomerIndexService,
    private readonly jobQueue: JobQueue,
  ) {}

  /**
   * Tao khach tren Haravan qua hang doi cong viec.
   *
   *   POST /api/v1/customers/200001220496/create
   *
   * Tra `202 Accepted` kem `jobId`. Worker goi Haravan, ghi MongoDB, day Elasticsearch; sau do
   * Haravan con gui webhook `customers/create` ve de xac nhan. FE theo doi bang
   * `GET /api/v1/orders/:orgId/jobs/:jobId`.
   */
  @Post(':orgId/create')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Tao khach hang tren Haravan' })
  async create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: CreateCustomerBody,
  ) {
    if (!body.phone?.trim() && !body.email?.trim()) {
      throw new BadRequestException(
        'Can nhap so dien thoai hoac email de tao khach hang',
      );
    }

    return this.queueCustomerJob(JOB_NAMES.CUSTOMER_CREATE, orgId, {
      body: body as Record<string, unknown>,
    });
  }

  /**
   * Sua khach tren Haravan qua hang doi cong viec.
   *
   *   PUT /api/v1/customers/200001220496/1176354931/update
   */
  @Put(':orgId/:customerId/update')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Sua khach hang tren Haravan' })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('customerId', ParseIntPipe) haravanCustomerId: number,
    @Body() body: UpdateCustomerBody,
  ) {
    return this.queueCustomerJob(JOB_NAMES.CUSTOMER_UPDATE, orgId, {
      haravanCustomerId,
      body: body as Record<string, unknown>,
    });
  }

  /** Day cong viec vao hang doi va tra `jobId` cho FE theo doi. */
  private async queueCustomerJob(
    name: string,
    orgId: number,
    payload: Record<string, unknown>,
  ) {
    const job = await this.jobQueue.enqueue(name, { orgId, ...payload }, {
      maxAttempts: 3,
    });
    return {
      queued: true,
      jobId: job.id,
      action: name,
      status: 'pending' as const,
    };
  }

  /**
   * Tim kiem khach bang Elasticsearch, tu lui ve MongoDB khi chua bat.
   *
   *   GET /api/v1/customers/search?orgId=200001220496&q=633
   *
   * `q` co ba so thi hieu la **ba so cuoi** cua so dien thoai, khong phai ba so bat ky.
   * Ket qua tra kem `engine` de biet `elasticsearch` hay `mongodb` da tra loi.
   */
  @Get('search')
  @ApiOperation({ summary: 'Tim khach theo 3 so cuoi, ten hoac email' })
  search(@Query() query: CustomerSearchDto) {
    return this.searchService.search({
      orgId: Number(query.orgId),
      q: query.q ?? '',
      page: query.page ? Number(query.page) : undefined,
      limit: query.limit ? Number(query.limit) : undefined,
      kind: query.kind as 'returning' | 'first_time' | 'all',
      sort: query.sort as 'newest' | 'lastSeen' | 'spent' | 'orders',
    });
  }

  /**
   * Nap lai toan bo khach tu MongoDB sang Elasticsearch.
   *
   *   POST /api/v1/customers/reindex
   *
   * Chi can chay mot lan sau khi bat Elasticsearch lan dau; cac thay doi sau do tu dong
   * dong bo qua hang doi cong viec.
   */
  @Post('reindex')
  @ApiOperation({ summary: 'Nap lai khach hang tu Mongo sang Elasticsearch' })
  reindex(@Body() body: CustomerReindexDto) {
    return this.indexService.reindexAll(body?.batchSize);
  }

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
