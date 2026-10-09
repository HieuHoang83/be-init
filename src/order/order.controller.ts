import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { User } from '../decorators/customize';
import { JobQueue } from '../queue/queue.service';
import { OrderService } from './order.service';
import { OrderActionsService } from './order-actions.service';
import { OrderQueryService } from './order-query.service';
import { extractOrder } from '../core/webhook-payload.util';
import { JOB_NAMES } from '../queue/queue.service';
import { WebhookPrivateService } from '../webhook-private/webhook-private.service';
import {
  CancelOrderBody,
  CloseOrderBody,
  ConfirmOrderBody,
  CreateRefundBody,
  CreateOrderBody,
  ListRefundsQuery,
  ListOrdersQuery,
  OpenOrderBody,
  UpdateOrderBody,
} from './dto/order.dto';

function parseFilterList(value?: string): string[] {
  return [...new Set((value ?? '').split(',').filter(Boolean))];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function customerNamePrefixPattern(value: string): RegExp {
  const accentedCharacters: Record<string, string> = {
    a: 'aáàảãạăắằẳẵặâấầẩẫậ',
    c: 'c',
    d: 'dđ',
    e: 'eéèẻẽẹêếềểễệ',
    i: 'iíìỉĩị',
    o: 'oóòỏõọôốồổỗộơớờởỡợ',
    u: 'uúùủũụưứừửữự',
    y: 'yýỳỷỹỵ',
  };
  const normalized = value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[đĐ]/g, 'd');
  const pattern = [...normalized]
    .map((character) => {
      const alternatives = accentedCharacters[character.toLowerCase()];
      if (!alternatives) return escapeRegex(character);
      return `[${alternatives}${alternatives.toUpperCase()}]`;
    })
    .join('');
  return new RegExp(`^${pattern}`, 'i');
}

/** API quản lý đơn hàng. */
@ApiTags('Haravan Orders')
@Controller('orders')
export class OrderController {
  constructor(
    private readonly orderService: OrderService,
    private readonly orderQuery: OrderQueryService,
    private readonly orderActions: OrderActionsService,
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
    const search = query.search?.trim().replace(/^#+/, '').trim();
    if (search) {
      const searchConditions: Record<string, unknown>[] = [
        { orderNumber: new RegExp(`^${escapeRegex(search)}`, 'i') },
        { orderName: new RegExp(`^${escapeRegex(search)}`, 'i') },
        { customerName: customerNamePrefixPattern(search) },
        { 'customer.fullName': customerNamePrefixPattern(search) },
        { 'customer.firstName': customerNamePrefixPattern(search) },
      ];
      if (/^\d+$/.test(search)) {
        const numericSearch = Number(search);
        if (Number.isSafeInteger(numericSearch)) {
          searchConditions.push({ haravanOrderId: numericSearch });
        }
      }
      const phonePrefix = search
        .replace(/\D/g, '')
        .replace(/^84(?=\d{9,})/, '0');
      if (phonePrefix.length >= 5) {
        searchConditions.push({
          phone: new RegExp(`^${escapeRegex(phonePrefix)}`),
        });
        searchConditions.push({
          'customer.phone': new RegExp(`^${escapeRegex(phonePrefix)}`),
        });
      }
      filter['$or'] = searchConditions;
    }
    if (query.financialStatus)
      filter['financialStatus'] = query.financialStatus;
    const financialStatuses = parseFilterList(query.financialStatuses);
    if (financialStatuses.length === 1) {
      filter['financialStatus'] = financialStatuses[0];
    } else if (financialStatuses.length > 1) {
      filter['financialStatus'] = { $in: financialStatuses };
    }
    const fulfillmentStatuses = parseFilterList(query.fulfillmentStatuses);
    if (fulfillmentStatuses.length) {
      const fulfillmentAlternatives: Record<string, unknown>[] = [];
      if (fulfillmentStatuses.includes('shipped')) {
        fulfillmentAlternatives.push({
          fulfillmentStatus: { $in: ['fulfilled', 'shipped'] },
        });
      }
      if (fulfillmentStatuses.includes('unshipped')) {
        fulfillmentAlternatives.push({
          fulfillmentStatus: {
            $in: [null, 'notfulfilled', 'unfulfilled', 'unshipped'],
          },
        });
      }
      if (fulfillmentStatuses.includes('partial')) {
        fulfillmentAlternatives.push({ fulfillmentStatus: 'partial' });
      }
      if (fulfillmentAlternatives.length === 1) {
        Object.assign(filter, fulfillmentAlternatives[0]);
      } else if (fulfillmentAlternatives.length > 1) {
        filter['$and'] = [
          ...((filter['$and'] as Record<string, unknown>[] | undefined) ?? []),
          { $or: fulfillmentAlternatives },
        ];
      }
    }
    const haravanStatuses = [
      ...(query.status && query.status !== 'any' ? [query.status] : []),
      ...parseFilterList(query.haravanStatuses),
    ].filter(
      (status, index, statuses) =>
        status !== 'any' && statuses.indexOf(status) === index,
    );
    if (haravanStatuses.length) {
      const haravanStatusAlternatives = haravanStatuses.flatMap((status) => {
        const missingPayloadStatus = {
          $or: [
            { 'payload.status': { $exists: false } },
            { 'payload.status': null },
            { 'payload.status': '' },
          ],
        };
        const alternatives: Record<string, unknown>[] = [
          { 'payload.status': status },
          { $and: [missingPayloadStatus, { haravanStatus: status }] },
        ];
        const legacyAlternatives: Record<string, unknown>[] = [];
        if (status === 'open') {
          legacyAlternatives.push(
            { cancelledStatus: 'uncancelled', closedStatus: 'unclosed' },
            {
              'payload.cancelled_status': 'uncancelled',
              'payload.closed_status': 'unclosed',
            },
          );
        } else if (status === 'cancelled') {
          legacyAlternatives.push(
            { cancelledStatus: { $in: ['cancelled', 'true'] } },
            { 'payload.cancelled_status': { $in: ['cancelled', 'true'] } },
            { 'payload.cancelled_at': { $exists: true, $ne: null } },
          );
        } else if (status === 'closed') {
          legacyAlternatives.push(
            { closedStatus: { $in: ['closed', 'true'] } },
            { 'payload.closed_status': { $in: ['closed', 'true'] } },
            { 'payload.closed_at': { $exists: true, $ne: null } },
          );
        }
        if (legacyAlternatives.length) {
          alternatives.push({
            $and: [missingPayloadStatus, { $or: legacyAlternatives }],
          });
        }
        return alternatives;
      });
      const existingAnd =
        (filter['$and'] as Record<string, unknown>[] | undefined) ?? [];
      existingAnd.push({ $or: haravanStatusAlternatives });
      filter['$and'] = existingAnd;
    }
    const customerOrderTypes = parseFilterList(query.customerOrderTypes);
    if (customerOrderTypes.length === 1) {
      const firstOrder = customerOrderTypes[0] === 'first';
      const existingAnd =
        (filter['$and'] as Record<string, unknown>[] | undefined) ?? [];
      filter['$and'] = [
        ...existingAnd,
        {
          $and: [
            {
              $or: [
                { 'customer.haravanId': { $exists: true, $gt: 0 } },
                {
                  'customer.email': {
                    $exists: true,
                    $nin: [null, ''],
                    $not: /^(guest|noreply|no.?reply)([+._-].*)?@/i,
                  },
                },
                {
                  'customer.phone': {
                    $exists: true,
                    $nin: [null, ''],
                  },
                },
                {
                  email: {
                    $exists: true,
                    $nin: [null, ''],
                    $not: /^(guest|noreply|no.?reply)([+._-].*)?@/i,
                  },
                },
                { phone: { $exists: true, $nin: [null, ''] } },
              ],
            },
            {
              $nor: [
                {
                  'customer.email': /^(guest|noreply|no.?reply)([+._-].*)?@/i,
                },
                { email: /^(guest|noreply|no.?reply)([+._-].*)?@/i },
                {
                  'customer.fullName':
                    /^(guest\b|khach le\b|khách lẻ\b|walk.?in\b)/i,
                },
                {
                  customerName: /^(guest\b|khach le\b|khách lẻ\b|walk.?in\b)/i,
                },
              ],
            },
          ],
        },
        {
          $expr: firstOrder
            ? {
                $eq: [
                  {
                    $cond: [
                      { $gt: [{ $ifNull: ['$customer.ordersCount', 0] }, 0] },
                      '$customer.ordersCount',
                      {
                        $add: [
                          { $ifNull: ['$processing.priorOrderCount', 0] },
                          1,
                        ],
                      },
                    ],
                  },
                  1,
                ],
              }
            : {
                $gt: [
                  {
                    $cond: [
                      { $gt: [{ $ifNull: ['$customer.ordersCount', 0] }, 0] },
                      '$customer.ordersCount',
                      {
                        $add: [
                          { $ifNull: ['$processing.priorOrderCount', 0] },
                          1,
                        ],
                      },
                    ],
                  },
                  1,
                ],
              },
        },
      ];
    }
    const confirmedStatuses = [
      ...new Set(
        (query.confirmedStatuses ?? '')
          .split(',')
          .filter(
            (status) => status === 'confirmed' || status === 'unconfirmed',
          ),
      ),
    ];
    if (
      confirmedStatuses?.length === 1 &&
      confirmedStatuses[0] === 'confirmed'
    ) {
      filter['payload.confirmed_status'] = 'confirmed';
    } else if (
      confirmedStatuses?.length === 1 &&
      confirmedStatuses[0] === 'unconfirmed'
    ) {
      filter['payload.confirmed_status'] = { $ne: 'confirmed' };
    } else if (
      !confirmedStatuses?.length &&
      query.confirmedStatus === 'confirmed'
    ) {
      filter['payload.confirmed_status'] = 'confirmed';
    } else if (
      !confirmedStatuses?.length &&
      query.confirmedStatus === 'unconfirmed'
    ) {
      filter['payload.confirmed_status'] = { $ne: 'confirmed' };
    }

    if (query.createdFrom || query.createdTo) {
      const createdAt: { $gte?: Date; $lt?: Date } = {};
      if (query.createdFrom) {
        createdAt.$gte = new Date(query.createdFrom);
      }
      if (query.createdTo) {
        createdAt.$lt = new Date(query.createdTo);
      }
      if (createdAt.$gte && createdAt.$lt && createdAt.$gte >= createdAt.$lt) {
        throw new BadRequestException(
          'Ngay bat dau khong duoc sau ngay ket thuc',
        );
      }
      filter['createdAt'] = createdAt;
    }

    return this.orderQuery.findOrders(
      filter,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('stats')
  @ApiOperation({ summary: 'Thong ke don hang' })
  async stats(@Query('orgId') orgId?: string) {
    const parsed = orgId ? Number(orgId) : undefined;
    return this.orderQuery.getStats(
      Number.isFinite(parsed) ? (parsed as number) : undefined,
    );
  }

  @Get('queue')
  @ApiOperation({ summary: 'Trang thai job queue' })
  getQueueStats() {
    return this.jobQueue.getStats();
  }

  @Get(':orgId/:haravanOrderId')
  @ApiOperation({ summary: 'Chi tiet don hang + nhat ky su kien' })
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

    const events = await this.orderQuery.findEvents(
      orgId,
      haravanOrderId,
      100,
    );
    return { order, events };
  }

  @Get(':orgId/:haravanOrderId/actions')
  @ApiOperation({ summary: 'Lich su thao tac cua don' })
  actions(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
  ) {
    return this.orderQuery.findActions(orgId, haravanOrderId, 200);
  }

  @Post(':orgId/create')
  @ApiOperation({ summary: 'Tao don hang tren Haravan' })
  create(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: CreateOrderBody,
  ) {
    return this.orderService.createOrder(orgId, body);
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
  /** Admin huỷ đơn, tuỳ chọn hoàn tiền / hoàn tồn kho. */
  @Post(':orgId/:haravanOrderId/cancel')
  @ApiOperation({ summary: 'Huy don hang tren Haravan' })
  async cancel(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: CancelOrderBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const order = await this.orderActions.cancelOrder({
      orgId,
      haravanOrderId,
      actor: body?.actor ?? user?.email ?? 'admin',
      amount: body?.amount,
      email: body?.email,
      reason: body?.reason,
      refund: body?.refund,
      restock: body?.restock,
      note: body?.note,
      ignoreCancelFulfillment: body?.ignore_cancel_fulfillment,
    });
    return { cancelled: true, order };
  }

  /** Đóng đơn. */
  @Post(':orgId/:haravanOrderId/close')
  @ApiOperation({ summary: 'Dong don hang' })
  async close(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: CloseOrderBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const order = await this.orderActions.closeOrder({
      orgId,
      haravanOrderId,
      actor: body?.actor ?? user?.email ?? 'admin',
      note: body?.note,
    });
    return { closed: true, order };
  }

  /** Mở lại đơn đã đóng. */
  @Post(':orgId/:haravanOrderId/open')
  @ApiOperation({ summary: 'Mo lai don hang' })
  async open(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: OpenOrderBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const order = await this.orderActions.openOrder({
      orgId,
      haravanOrderId,
      actor: body?.actor ?? user?.email ?? 'admin',
    });
    return { opened: true, order };
  }

  /** Cập nhật thông tin đơn (không đổi line_items / financial_status). */
  @Put(':orgId/:haravanOrderId')
  @ApiOperation({ summary: 'Cap nhat don hang' })
  async update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: UpdateOrderBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const order = await this.orderActions.updateOrder({
      orgId,
      haravanOrderId,
      actor: body?.actor ?? user?.email ?? 'admin',
      note: body?.note,
      noteAttributes: body?.note_attributes,
      email: body?.email,
      phone: body?.phone,
    });
    return { updated: true, order };
  }

  /** Lịch sử hoàn tiền của đơn. */
  @Get(':orgId/:haravanOrderId/refunds')
  @ApiOperation({ summary: 'Danh sach giao dich hoan tien' })
  listRefunds(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Query() query: ListRefundsQuery,
  ) {
    return this.orderActions.listRefunds(
      orgId,
      haravanOrderId,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  /** Chi tiết một giao dịch hoàn tiền. */
  @Get(':orgId/:haravanOrderId/refunds/:refundId')
  @ApiOperation({ summary: 'Chi tiet giao dich hoan tien' })
  getRefund(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Param('refundId', ParseIntPipe) refundId: number,
  ) {
    return this.orderActions.getRefund(orgId, haravanOrderId, refundId);
  }

  /** Hoàn tiền cho đơn đã thu tiền. */
  @Post(':orgId/:haravanOrderId/refunds')
  @ApiOperation({ summary: 'Hoan tien don hang' })
  async refund(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: CreateRefundBody,
    @User() user?: { id?: number; email?: string },
  ) {
    const transaction = body?.transactions?.[0];
    const order = await this.orderActions.refundOrder({
      orgId,
      haravanOrderId,
      actor: body?.actor ?? user?.email ?? 'admin',
      amount: transaction?.amount,
      gateway: transaction?.gateway,
      note: transaction?.note ?? body?.note,
    });
    return { refunded: true, order };
  }

  @Get(':orgId/:haravanOrderId/transactions')
  @ApiOperation({ summary: 'Danh sach giao dich cua don hang' })
  listTransactions(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
  ) {
    return this.orderActions.listTransactions(orgId, haravanOrderId);
  }

  @Post(':orgId/:haravanOrderId/transactions')
  @ApiOperation({ summary: 'Tao giao dich cho don hang (thanh toan)' })
  async createTransaction(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('haravanOrderId', ParseIntPipe) haravanOrderId: number,
    @Body() body: { amount: number; kind: string },
  ) {
    const transaction = await this.orderActions.createTransaction({
      orgId,
      haravanOrderId,
      amount: body?.amount ?? 0,
      kind: body?.kind ?? 'capture',
    });
    return { transaction, success: true };
  }

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
