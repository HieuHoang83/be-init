import { BadRequestException } from '@nestjs/common';
import { validateSync } from 'class-validator';
import { OrderController } from './order.controller';
import { OrderService } from './services/order.service';
import { OrderActionsService } from './services/order-actions.service';
import { OrderQueryService } from './services/order-query.service';
import { ListOrdersQuery } from './dto/order.dto';
import {
  CreateTransactionBody,
  ListTransactionsQuery,
  TRANSACTION_KINDS,
} from './dto/order.dto';

describe('OrderController transactions', () => {
  const listTransactions = jest.fn();
  const getTransaction = jest.fn();
  const controller = new OrderController(
    {} as unknown as OrderService,
    {} as unknown as OrderQueryService,
    { listTransactions, getTransaction } as unknown as OrderActionsService,
    {} as never,
    {} as never,
  );

  beforeEach(() => {
    listTransactions.mockReset();
    getTransaction.mockReset();
  });

  it('forwards the fields filter when listing transactions', async () => {
    const query: ListTransactionsQuery = { fields: 'id,kind,amount' };
    await controller.listTransactions(1, 2, query);

    expect(listTransactions).toHaveBeenCalledWith(1, 2, query);
  });

  it('reads a single transaction of an order', async () => {
    getTransaction.mockResolvedValue({ transaction: { id: 9 } });

    await expect(controller.getTransaction(1, 2, 9, {})).resolves.toEqual({
      transaction: { id: 9 },
    });
    expect(getTransaction).toHaveBeenCalledWith(1, 2, 9, {});
  });

  it('accepts only the documented transaction kinds', () => {
    expect(TRANSACTION_KINDS).toEqual([
      'pending',
      'authorization',
      'sale',
      'capture',
      'void',
      'refund',
    ]);

    const errors = validateSync(
      Object.assign(new CreateTransactionBody(), {
        kind: 'not-a-kind',
        amount: 10,
      }),
    );
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects a negative transaction amount', () => {
    const errors = validateSync(
      Object.assign(new CreateTransactionBody(), {
        kind: 'sale',
        amount: -1,
      }),
    );
    expect(errors.length).toBeGreaterThan(0);
  });
});

describe('OrderController list confirmation filter', () => {
  const findOrders = jest.fn();
  const controller = new OrderController(
    { findOrders } as unknown as OrderService,
    { findOrders } as unknown as OrderQueryService,
    {} as unknown as OrderActionsService,
    {} as never,
    {} as never,
  );

  beforeEach(() => {
    findOrders.mockReset();
    findOrders.mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 });
  });

  it('includes orders with missing or null confirmation status in unconfirmed results', async () => {
    await controller.list({ confirmedStatus: 'unconfirmed' });

    expect(findOrders).toHaveBeenCalledWith(
      { 'payload.confirmed_status': { $ne: 'confirmed' } },
      1,
      20,
    );
  });

  it('matches only confirmed orders for the confirmed filter', async () => {
    await controller.list({ confirmedStatus: 'confirmed' });

    expect(findOrders).toHaveBeenCalledWith(
      { 'payload.confirmed_status': 'confirmed' },
      1,
      20,
    );
  });

  it('searches order numbers, Haravan IDs, phone prefixes, and accent-insensitive customer name prefixes', async () => {
    await controller.list({ search: '#Nguyen Van' } as ListOrdersQuery);

    const filter = findOrders.mock.calls[0][0];
    expect(filter.$or).toHaveLength(5);
    expect(filter.$or[0].orderNumber).toEqual(/^Nguyen Van/i);
    expect(filter.$or[1].orderName).toEqual(/^Nguyen Van/i);
    expect(filter.$or[2].customerName).toBeInstanceOf(RegExp);
    expect(filter.$or[2].customerName.test('Nguyễn Văn A')).toBe(true);
    expect(filter.$or[2].customerName.test('NGUYEN VAN A')).toBe(true);
    expect(filter.$or[3]['customer.fullName']).toBeInstanceOf(RegExp);
    expect(filter.$or[4]['customer.firstName']).toBeInstanceOf(RegExp);
  });

  it('searches numeric terms against order IDs and phone prefixes', async () => {
    await controller.list({ search: '0961277630' } as ListOrdersQuery);

    const filter = findOrders.mock.calls[0][0];
    expect(filter.$or).toContainEqual({ haravanOrderId: 961277630 });
    expect(filter.$or).toContainEqual({ phone: /^0961277630/ });
    expect(filter.$or).toContainEqual({ 'customer.phone': /^0961277630/ });
  });

  it('normalizes international phone prefixes before searching', async () => {
    await controller.list({ search: '+84 961 277 630' } as ListOrdersQuery);

    const filter = findOrders.mock.calls[0][0];
    expect(filter.$or).toContainEqual({ phone: /^0961277630/ });
    expect(filter.$or).toContainEqual({ 'customer.phone': /^0961277630/ });
  });

  it('treats selecting multiple confirmation statuses as all selected statuses', async () => {
    await controller.list({
      confirmedStatuses: 'confirmed,unconfirmed',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith({}, 1, 20);
  });

  it('filters a single selected confirmation status', async () => {
    await controller.list({
      confirmedStatuses: 'confirmed',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith(
      { 'payload.confirmed_status': 'confirmed' },
      1,
      20,
    );
  });

  it('applies documented payment and fulfillment statuses', async () => {
    await controller.list({
      financialStatuses: 'pending,paid',
      fulfillmentStatuses: 'shipped',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith(
      {
        financialStatus: { $in: ['pending', 'paid'] },
        fulfillmentStatus: { $in: ['fulfilled', 'shipped'] },
      },
      1,
      20,
    );
  });

  it('maps the documented unshipped fulfillment filter to stored Haravan statuses', async () => {
    await controller.list({
      fulfillmentStatuses: 'unshipped',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith(
      {
        fulfillmentStatus: {
          $in: [null, 'notfulfilled', 'unfulfilled', 'unshipped'],
        },
      },
      1,
      20,
    );
  });

  it('maps documented Haravan lifecycle statuses separately from internal order processing', async () => {
    await controller.list({
      haravanStatuses: 'cancelled',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith(
      {
        $and: [
          {
            $or: [
              { 'payload.status': 'cancelled' },
              {
                $and: [
                  {
                    $or: [
                      { 'payload.status': { $exists: false } },
                      { 'payload.status': null },
                      { 'payload.status': '' },
                    ],
                  },
                  { haravanStatus: 'cancelled' },
                ],
              },
              {
                $and: [
                  {
                    $or: [
                      { 'payload.status': { $exists: false } },
                      { 'payload.status': null },
                      { 'payload.status': '' },
                    ],
                  },
                  {
                    $or: [
                      { cancelledStatus: { $in: ['cancelled', 'true'] } },
                      {
                        'payload.cancelled_status': {
                          $in: ['cancelled', 'true'],
                        },
                      },
                      { 'payload.cancelled_at': { $exists: true, $ne: null } },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      },
      1,
      20,
    );
  });

  it('maps uncancelled and unclosed legacy orders to the Haravan open filter', async () => {
    await controller.list({ haravanStatuses: 'open' } as ListOrdersQuery);

    const statusFilter = findOrders.mock.calls[0][0].$and[0].$or;
    expect(statusFilter).toContainEqual({ 'payload.status': 'open' });
    expect(statusFilter).toContainEqual({
      $and: [
        {
          $or: [
            { 'payload.status': { $exists: false } },
            { 'payload.status': null },
            { 'payload.status': '' },
          ],
        },
        {
          $or: [
            { cancelledStatus: 'uncancelled', closedStatus: 'unclosed' },
            {
              'payload.cancelled_status': 'uncancelled',
              'payload.closed_status': 'unclosed',
            },
          ],
        },
      ],
    });
  });

  it('treats the documented any lifecycle status as no status restriction', async () => {
    await controller.list({ status: 'any' } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith({}, 1, 20);
  });

  it('validates only the documented Haravan status filters', () => {
    const validQuery = Object.assign(new ListOrdersQuery(), {
      financialStatuses:
        'pending,paid,partially_paid,refunded,voided,partially_refunded',
      fulfillmentStatuses: 'unshipped,shipped,partial',
      haravanStatuses: 'open,closed,cancelled',
      status: 'any',
    });
    const invalidQuery = Object.assign(new ListOrdersQuery(), {
      financialStatuses: 'authorized',
      fulfillmentStatuses: 'fulfilled,restocked',
      haravanStatuses: 'processing',
      status: 'processing',
      orderStatuses: 'processing',
    });

    expect(validateSync(validQuery)).toHaveLength(0);
    expect(validateSync(invalidQuery).map((error) => error.property)).toEqual(
      expect.arrayContaining([
        'financialStatuses',
        'fulfillmentStatuses',
        'haravanStatuses',
        'status',
      ]),
    );
  });

  it('filters the first customer order only for identifiable customers', async () => {
    await controller.list({ customerOrderTypes: 'first' } as ListOrdersQuery);

    const filter = findOrders.mock.calls[0][0];
    const identityFilter = filter.$and[0].$and;
    expect(identityFilter[0].$or).toContainEqual({
      'customer.haravanId': { $exists: true, $gt: 0 },
    });
    expect(identityFilter[0].$or).toContainEqual({
      'customer.email': {
        $exists: true,
        $nin: [null, ''],
        $not: /^(guest|noreply|no.?reply)([+._-].*)?@/i,
      },
    });
    expect(identityFilter[1].$nor).toEqual(
      expect.arrayContaining([
        { 'customer.email': /^(guest|noreply|no.?reply)([+._-].*)?@/i },
        { email: /^(guest|noreply|no.?reply)([+._-].*)?@/i },
        { 'customer.fullName': /^(guest\b|khach le\b|khách lẻ\b|walk.?in\b)/i },
        { customerName: /^(guest\b|khach le\b|khách lẻ\b|walk.?in\b)/i },
      ]),
    );
    expect(filter.$and[1].$expr.$eq[1]).toBe(1);
  });

  it('uses a start-inclusive and end-exclusive order creation range', async () => {
    await controller.list({
      createdFrom: '2026-10-05T17:00:00.000Z',
      createdTo: '2026-10-06T17:00:00.000Z',
    } as ListOrdersQuery);

    expect(findOrders).toHaveBeenCalledWith(
      {
        createdAt: {
          $gte: new Date('2026-10-05T17:00:00.000Z'),
          $lt: new Date('2026-10-06T17:00:00.000Z'),
        },
      },
      1,
      20,
    );
  });

  it('rejects a date range whose start is after its end', async () => {
    await expect(
      controller.list({
        createdFrom: '2026-10-07T00:00:00.000Z',
        createdTo: '2026-10-06T00:00:00.000Z',
      } as ListOrdersQuery),
    ).rejects.toThrow(BadRequestException);
  });
});
