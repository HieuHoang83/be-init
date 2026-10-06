import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseIntPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { User } from '../decorators/customize';
import { JobQueue } from '../queue/queue.service';
import { OrderService } from './order.service';
import { extractOrder } from '../core/webhook-payload.util';
import { JOB_NAMES } from '../queue/queue.service';
import { WebhookPrivateService } from '../webhook-private/webhook-private.service';
import { ConfirmOrderBody, ListOrdersQuery } from './dto/order.dto';

/** API quản lý đơn hàng. */
@ApiTags('Haravan Orders')
@Controller('orders')
export class OrderController {
  constructor(
    private readonly orderService: OrderService,
    private readonly webhookService: WebhookPrivateService,
    private readonly jobQueue: JobQueue,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Danh sach don hang da luu',
    description:
      'Moi don co name (ten don Haravan) va customerOrderNumber (uu tien customer.orders_count tu payload, du phong bang lich su BE).',
  })
  @ApiQuery({ name: 'orgId', required: false, type: Number })
  async list(@Query() query: ListOrdersQuery) {
    const filter: Record<string, unknown> = {};

    if (query.orgId !== undefined) filter['orgId'] = query.orgId;
    if (query.email) filter['customer.email'] = query.email.toLowerCase();
    if (query.orderNumber) filter['orderNumber'] = query.orderNumber;
    if (query.status) filter['status'] = query.status;
    if (query.financialStatus)
      filter['financialStatus'] = query.financialStatus;
    if (query.confirmedStatus)
      filter['confirmedStatus'] = query.confirmedStatus;

    return this.orderService.findOrders(
      filter,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('stats')
  @ApiOperation({ summary: 'Thong ke don hang' })
  async stats(@Query('orgId') orgId?: string) {
    const parsed = orgId ? Number(orgId) : undefined;
    return this.orderService.getStats(
      Number.isFinite(parsed) ? (parsed as number) : undefined,
    );
  }

  @Get('queue')
  @ApiOperation({ summary: 'Trang thai job queue' })
  getQueueStats() {
    return this.jobQueue.getStats();
  }

  @Get(':orgId/:haravanOrderId')
  @ApiOperation({ summary: 'Chi tiet don hang + lich su thao tac' })
  async detail(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
  ) {
    const order = await this.orderService.findOrderById(orgId, haravanOrderId);
    if (!order) {
      throw new NotFoundException(
        `Khong tim thay don ${haravanOrderId} cua org ${orgId}`,
      );
    }

    const actions = await this.orderService.findActions(
      orgId,
      haravanOrderId,
      100,
    );
    return { order, actions };
  }

  @Get(':orgId/:haravanOrderId/actions')
  @ApiOperation({ summary: 'Lich su thao tac cua don' })
  actions(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
  ) {
    return this.orderService.findActions(orgId, haravanOrderId, 200);
  }

  /** Admin xác nhận đơn thủ công. */
  @Post(':orgId/:haravanOrderId/confirm')
  @ApiOperation({ summary: 'Xac nhan don thu cong qua Haravan API' })
  async confirm(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: ConfirmOrderBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const result = await this.orderService.confirmOrder({
      orgId,
      haravanOrderId,
      manual: true,
      actor: body?.actor ?? user?.email ?? 'admin',
      force: body?.force ?? false,
      source: 'manual',
    });

    return {
      confirmed: result.confirmed,
      orderNumber: result.order.orderNumber,
      orderName: result.order.orderName,
      status: result.order.status,
      processing: result.order.processing,
      actionLogId: result.actionLogId,
    };
  }

  /** Chạy lại webhook lỗi. */
  @Post('webhooks/:eventId/replay')
  @ApiOperation({ summary: 'Chay lai xu ly mot webhook da nhan' })
  async replay(@Param('eventId') eventId: string) {
    if (!eventId?.trim()) {
      throw new BadRequestException('Thieu eventId');
    }

    const event = await this.webhookService.findById(eventId);
    if (!event) {
      throw new NotFoundException(`Khong tim thay webhook event ${eventId}`);
    }

    const { orgId, order } = extractOrder({}, event.payload);

    const job = await this.jobQueue.enqueue(JOB_NAMES.ORDER_CREATED, {
      orgId,
      haravanOrderId: order.id,
      webhookEventId: eventId,
      topic: event.topic,
    });

    return { queued: true, jobId: job.id, eventId };
  }
}
