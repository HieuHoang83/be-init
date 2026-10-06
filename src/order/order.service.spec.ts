import { ConfigModule } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { OrderService } from './order.service';
import {
  Order,
  OrderAction,
  OrderActionDocument,
  OrderDocument,
  OrderStatus,
  SkipReason,
} from './order.entity';
import { Customer } from './customer.entity';
import { appConfig } from '../config';
import { ApiClient } from '../api/api.service';

describe('OrderService - evaluateConfirmEligibility', () => {
  let service: OrderService;

  const queryMock = (value: unknown) => ({
    exec: () => Promise.resolve(value),
  });

  const apiMock = {
    getOrder: jest.fn(),
    confirmOrder: jest.fn().mockResolvedValue({
      body: { order: { id: 2 } },
      statusCode: 200,
      durationMs: 12,
    }),
  };

  const orderModel = {
    countDocuments: jest.fn((_filter: Record<string, unknown>) => queryMock(0)),
    aggregate: jest.fn(() => queryMock([])),
    find: jest.fn(() => ({
      sort: () => ({
        skip: () => ({
          limit: () => queryMock([]),
        }),
      }),
    })),
    findOne: jest.fn(() => queryMock(null)),
    findOneAndUpdate: jest.fn(
      (
        _filter: unknown,
        _update: unknown,
        _options: unknown,
      ) => queryMock(null),
    ),
  };

  const actionModel = {
    create: jest.fn(async (doc: unknown) => ({
      _id: 'action-id',
      ...(doc as object),
    })),
  };

  const customerModel = {
    findOne: jest.fn(() => ({
      lean: () => queryMock(null),
    })),
    updateOne: jest.fn(
      (_filter: unknown, _update: unknown) =>
        queryMock({ acknowledged: true }),
    ),
    create: jest.fn(async (doc: unknown) => ({
      _id: 'c1',
      ...(doc as object),
    })),
  };

  const buildOrder = (overrides: Partial<Order> = {}): OrderDocument =>
    ({
      _id: 'o1',
      orgId: 1,
      haravanOrderId: 2,
      status: OrderStatus.PENDING,
      processing: {},
      createdAt: new Date('2026-01-02'),
      save: jest.fn().mockResolvedValue(true),
      customer: {
        haravanId: 55,
        email: 'khach@example.com',
        ordersCount: 2,
        totalSpent: 500000,
      },
      financialStatus: 'paid',
      confirmedStatus: 'unconfirmed',
      totalPrice: 200000,
      ...overrides,
    } as unknown as OrderDocument);

  const makeService = async (
    rule: Partial<{ minPriorOrders: number; minPriorSpent: number }> = {},
  ) => {
    process.env.HARAVAN_MIN_PRIOR_ORDERS = String(rule.minPriorOrders ?? 1);
    process.env.HARAVAN_MIN_PRIOR_SPENT = String(rule.minPriorSpent ?? 0);

    const moduleRef = await Test.createTestingModule({
      imports: [ConfigModule.forFeature(appConfig)],
      providers: [
        OrderService,
        { provide: ApiClient, useValue: apiMock },
        { provide: getModelToken(Order.name), useValue: orderModel },
        { provide: getModelToken(OrderAction.name), useValue: actionModel },
        { provide: getModelToken(Customer.name), useValue: customerModel },
      ],
    }).compile();

    return moduleRef.get(OrderService);
  };

  beforeEach(() => {
    jest.clearAllMocks();
    orderModel.countDocuments.mockImplementation(() => queryMock(0));
    orderModel.aggregate.mockImplementation(() => queryMock([]));
    orderModel.findOne.mockImplementation(() => queryMock(null));
  });

  describe('du dieu kien de xac nhan', () => {
    it('khach mua lai (orders_count=2) -> confirm', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      orderModel.aggregate.mockImplementation(() =>
        queryMock([{ total: 300000 }]),
      );
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder(),
      );

      expect(decision).toMatchObject({
        shouldConfirm: true,
        isReturningCustomer: true,
        priorOrderCount: 1,
        skipReason: SkipReason.NONE,
      });
    });

    it('khach mua nhieu lan -> dem order truoc tu DB, bo qua orders_count', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(6));
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({
          customer: {
            haravanId: 55,
            ordersCount: 7,
            totalSpent: 3000000,
          } as Order['customer'],
        }),
      );

      expect(decision.priorOrderCount).toBe(6);
      expect(decision.shouldConfirm).toBe(true);
    });

    it('dat nguong minPriorOrders = 3 -> can it nhat 3 don truoc', async () => {
      service = await makeService({ minPriorOrders: 3 });
      orderModel.countDocuments.mockImplementation(() => queryMock(3));

      const enough = await service.evaluateConfirmEligibility(
        1,
        buildOrder({
          customer: { haravanId: 55, ordersCount: 4 } as Order['customer'],
        }),
      );
      expect(enough.shouldConfirm).toBe(true);

      orderModel.countDocuments.mockImplementation(() => queryMock(2));
      const notEnough = await service.evaluateConfirmEligibility(
        1,
        buildOrder({
          customer: { haravanId: 55, ordersCount: 3 } as Order['customer'],
        }),
      );
      expect(notEnough.shouldConfirm).toBe(false);
      expect(notEnough.skipReason).toBe(SkipReason.NOT_ENOUGH_PRIOR_ORDERS);
    });
  });

  describe('luu ten order', () => {
    it('giu name goc khi order_number null', async () => {
      const storedOrder = { orderNumber: '#10005', orderName: '#10005' };
      orderModel.findOne.mockImplementation(
        () => ({ select: () => ({ lean: () => queryMock(null) }) } as never),
      );
      orderModel.findOneAndUpdate.mockImplementation(
        () => queryMock(storedOrder) as never,
      );
      service = await makeService();

      const result = await service.upsertOrder(1, {
        id: 1849587434,
        name: '#10005',
        order_number: null,
      });

      expect(result.order.orderName).toBe('#10005');
      expect(orderModel.findOneAndUpdate).toHaveBeenCalledWith(
        { orgId: 1, haravanOrderId: 1849587434 },
        expect.objectContaining({
          $set: expect.objectContaining({
            orderName: '#10005',
            orderNumber: '#10005',
          }),
        }),
        expect.any(Object),
      );
    });
  });

  describe('giu orders_count tai thoi diem tao don', () => {
    const makeUpsertQuery = () => {
      orderModel.findOne.mockImplementation(
        () => ({ select: () => ({ lean: () => queryMock(null) }) } as never),
      );
      const storedOrder = { customer: { ordersCount: 2 } };
      orderModel.findOneAndUpdate.mockImplementation(
        () => queryMock(storedOrder) as never,
      );
    };

    it('luu orders_count tu webhook orders/create', async () => {
      makeUpsertQuery();
      service = await makeService();

      await service.upsertOrder(
        1,
        {
          id: 200,
          customer: { id: 55, orders_count: 2 },
        },
        'webhook',
        'orders/create',
      );

      expect(orderModel.findOneAndUpdate).toHaveBeenCalledWith(
        { orgId: 1, haravanOrderId: 200 },
        expect.objectContaining({
          $set: expect.objectContaining({
            'customer.ordersCount': 2,
          }),
        }),
        expect.any(Object),
      );
    });

    it('khong ghi de orders_count tu webhook cap nhat trang thai', async () => {
      makeUpsertQuery();
      service = await makeService();

      await service.upsertOrder(
        1,
        {
          id: 200,
          customer: { id: 55, orders_count: 3 },
        },
        'webhook',
        'orders/updated',
      );

      const update = orderModel.findOneAndUpdate.mock.calls[0][1] as {
        $set: Record<string, unknown>;
      };
      expect(update.$set).not.toHaveProperty('customer.ordersCount');
    });

    it('khong lay orders_count tu orders/updated khi tao ban ghi khach moi', async () => {
      service = await makeService();

      await service.upsertCustomer(
        1,
        {
          id: 200,
          total_price: 250000,
          customer: { id: 55, orders_count: 8 },
        },
        'orders/updated',
      );

      expect(customerModel.create).toHaveBeenCalledWith(
        expect.objectContaining({ haravanOrdersCount: 0 }),
      );
    });

    it('chi cap nhat count khach tu webhook orders/create', async () => {
      service = await makeService();
      customerModel.findOne.mockImplementation(() => ({
        lean: () => queryMock({ _id: 'customer-1' }),
      }));

      await service.upsertCustomer(
        1,
        {
          id: 201,
          customer: { id: 55, orders_count: 4 },
        },
        'orders/updated',
      );
      const updateEvent = customerModel.updateOne.mock.calls[0][1] as {
        $set: Record<string, unknown>;
      };
      expect(updateEvent.$set).not.toHaveProperty('haravanOrdersCount');

      await service.upsertCustomer(
        1,
        {
          id: 200,
          customer: { id: 55, orders_count: 2 },
        },
        'orders/create',
      );
      const createEvent = customerModel.updateOne.mock.calls[1][1] as {
        $set: Record<string, unknown>;
      };
      expect(createEvent.$set.haravanOrdersCount).toBe(2);
    });

    it('luon cap nhat ho so khach khi xu ly webhook don', async () => {
      const order = buildOrder({ customer: undefined });
      orderModel.findOne.mockImplementation(
        () => ({ select: () => ({ lean: () => queryMock(null) }) }) as never,
      );
      orderModel.findOneAndUpdate.mockImplementation(
        () => queryMock(order) as never,
      );
      service = await makeService();
      const upsertCustomer = jest.spyOn(service, 'upsertCustomer');

      await service.processIncomingOrder({
        orgId: 1,
        payload: { id: 2 },
        topic: 'orders/updated',
      });

      expect(upsertCustomer).toHaveBeenCalledWith(
        1,
        { id: 2 },
        'orders/updated',
      );
    });
  });

  describe('danh sach don hang', () => {
    it('uu tien customer.orders_count tu payload lam so thu tu don', async () => {
      const order = buildOrder({
        orderName: '#10015',
        orderNumber: '#10015',
        customer: {
          haravanId: 55,
          ordersCount: 7,
        } as Order['customer'],
        processing: {
          reason: SkipReason.FIRST_TIME_BUYER,
          isReturningCustomer: true,
          priorOrderCount: 2,
          priorSpent: 500000,
        },
      });
      order.toObject = () => ({
        orderName: '#10015',
        orderNumber: '#10015',
        processing: order.processing,
      }) as never;
      orderModel.find.mockImplementation(
        () => ({
          sort: () => ({
            skip: () => ({
              limit: () => queryMock([order]),
            }),
          }),
        }) as never,
      );
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();

      const result = await service.findOrders({}, 1, 20);

      expect(result.items[0]).toMatchObject({
        name: '#10015',
        priorOrderCount: 2,
        customerOrderNumber: 7,
      });
    });

    it('du phong bang lich su BE khi payload khong co orders_count', async () => {
      const order = buildOrder({
        orderName: '#10015',
        customer: {
          haravanId: 55,
        } as Order['customer'],
        processing: {
          reason: SkipReason.FIRST_TIME_BUYER,
          isReturningCustomer: true,
          priorOrderCount: 2,
          priorSpent: 500000,
        },
      });
      order.toObject = () => ({
        orderName: '#10015',
        processing: order.processing,
      }) as never;
      orderModel.find.mockImplementation(
        () => ({
          sort: () => ({
            skip: () => ({
              limit: () => queryMock([order]),
            }),
          }),
        }) as never,
      );
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();

      const result = await service.findOrders({}, 1, 20);

      expect(result.items[0]).toMatchObject({
        name: '#10015',
        customerOrderNumber: 3,
      });
    });

    it('khong gan so thu tu neu don khong co dinh danh khach', async () => {
      const order = buildOrder({
        orderName: '#10016',
        customer: undefined,
        email: undefined,
        phone: undefined,
        processing: {
          reason: SkipReason.NO_CUSTOMER,
          isReturningCustomer: false,
          priorOrderCount: 0,
          priorSpent: 0,
        },
      });
      order.toObject = () => ({
        orderName: '#10016',
        processing: order.processing,
      }) as never;
      orderModel.find.mockImplementation(
        () => ({
          sort: () => ({
            skip: () => ({
              limit: () => queryMock([order]),
            }),
          }),
        }) as never,
      );
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();

      const result = await service.findOrders({}, 1, 20);

      expect(result.items[0]).toMatchObject({
        name: '#10016',
        customerOrderNumber: null,
      });
    });
  });

  describe('khong du dieu kien', () => {
    it('khach moi (orders_count=1) -> skip first_time_buyer', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(0));
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({
          customer: {
            haravanId: 55,
            ordersCount: 1,
            totalSpent: 200000,
          } as Order['customer'],
        }),
      );

      expect(decision).toMatchObject({
        shouldConfirm: false,
        isReturningCustomer: false,
        priorOrderCount: 0,
        skipReason: SkipReason.FIRST_TIME_BUYER,
      });
    });

    it('don chua thanh toan van duoc danh gia theo cac rule khac', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({ financialStatus: 'pending' }),
      );

      expect(decision.skipReason).toBe(SkipReason.NONE);
      expect(decision.shouldConfirm).toBe(true);
    });

    it('don da confirmed o Harovan -> skip already_confirmed', async () => {
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({ confirmedStatus: 'confirmed' }),
      );

      expect(decision.skipReason).toBe(SkipReason.ALREADY_CONFIRMED);
    });

    it('don da huy -> skip order_cancelled', async () => {
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({ cancelledStatus: 'cancelled' }),
      );

      expect(decision.skipReason).toBe(SkipReason.ORDER_CANCELLED);
    });

    it('khong co customer -> skip no_customer', async () => {
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({ customer: undefined }),
      );

      expect(decision.skipReason).toBe(SkipReason.NO_CUSTOMER);
    });

    it('chua dat nguong chi tieu -> skip not_enough_prior_spent', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      orderModel.aggregate.mockImplementation(() =>
        queryMock([{ total: 100000 }]),
      );
      service = await makeService({ minPriorSpent: 1000000 });
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder(),
      );

      expect(decision.shouldConfirm).toBe(false);
      expect(decision.isReturningCustomer).toBe(true);
      expect(decision.skipReason).toBe(SkipReason.NOT_ENOUGH_PRIOR_SPENT);
    });
  });

  describe('dem order truoc tu DB', () => {
    it('dem cac order da luu, khong phu thuoc orders_count', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(3));
      orderModel.aggregate.mockImplementation(() =>
        queryMock([{ total: 900000 }]),
      );

      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({
          customer: { haravanId: 55 } as Order['customer'],
        }),
      );

      expect(orderModel.countDocuments).toHaveBeenCalled();
      expect(decision).toMatchObject({
        shouldConfirm: true,
        priorOrderCount: 3,
        priorSpent: 900000,
      });
    });

    it('khong co haravanId/email nhung co phone -> van dem order trong DB', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(2));
      service = await makeService();
      const decision = await service.evaluateConfirmEligibility(
        1,
        buildOrder({ customer: { phone: '0961234567' } as Order['customer'] }),
      );

      expect(decision.shouldConfirm).toBe(true);
      expect(decision.priorOrderCount).toBe(2);
      expect(orderModel.countDocuments).toHaveBeenCalled();
    });

    it('chi dem order khong huy va loai order hien tai', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();

      await service.countPriorOrders(1, buildOrder());

      const filter = orderModel.countDocuments.mock.calls[0][0];
      expect(filter).toMatchObject({
        status: { $ne: OrderStatus.CANCELLED },
        haravanOrderId: { $ne: 2 },
      });
      expect(filter).not.toHaveProperty('financialStatus');
    });
  });

  describe('xac nhan don', () => {
    it('goi Harovan API khi du dieu kien', async () => {
      orderModel.countDocuments.mockImplementation(() => queryMock(1));
      service = await makeService();
      const order = buildOrder();
      orderModel.findOne.mockImplementation(() => queryMock(order));

      const res = await service.confirmOrder({
        orgId: 1,
        haravanOrderId: 2,
        manual: false,
      });

      expect(apiMock.confirmOrder).toHaveBeenCalledWith(1, 2);
      expect(res.confirmed).toBe(true);
      expect(order.confirmedStatus).toBe('confirmed');
    });

    it('force=true bo qua rule, xac nhan du khach moi', async () => {
      service = await makeService();
      orderModel.findOne.mockImplementation(() => queryMock(buildOrder()));
      const res = await service.confirmOrder({
        orgId: 1,
        haravanOrderId: 2,
        manual: true,
        actor: 'admin',
        force: true,
      });

      expect(apiMock.confirmOrder).toHaveBeenCalled();
      expect(res.confirmed).toBe(true);
    });

    it('API that bai -> nem loi de queue retry', async () => {
      apiMock.confirmOrder.mockRejectedValueOnce(new Error('Harovan 500'));
      service = await makeService();
      orderModel.findOne.mockImplementation(() => queryMock(buildOrder()));

      await expect(
        service.confirmOrder({ orgId: 1, haravanOrderId: 2, force: true }),
      ).rejects.toThrow(/Harovan 500/);
    });
  });
});
