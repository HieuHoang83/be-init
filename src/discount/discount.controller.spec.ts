import { DiscountController } from './discount.controller';
import { DiscountService } from './discount.service';

describe('DiscountController', () => {
  const discounts = {
    list: jest.fn(),
    getOne: jest.fn(),
    create: jest.fn(),
    enable: jest.fn(),
    disable: jest.fn(),
    remove: jest.fn(),
  };
  const controller = new DiscountController(
    discounts as unknown as DiscountService,
  );

  beforeEach(() => {
    jest.resetAllMocks();
    discounts.list.mockResolvedValue({ discounts: [] });
    discounts.getOne.mockResolvedValue({ discount: { id: 1016875801 } });
    discounts.create.mockResolvedValue({ discount: { id: 1017981791 } });
    discounts.enable.mockResolvedValue({ discount: {} });
    discounts.disable.mockResolvedValue({ discount: {} });
    discounts.remove.mockResolvedValue({});
  });

  it('list forward query limit/page/code', async () => {
    await controller.list(1, { page: '1', code: 'SUMMER', limit: '20' });

    expect(discounts.list).toHaveBeenCalledWith(1, {
      page: '1',
      code: 'SUMMER',
      limit: '20',
    });
  });

  it('create forward body { discount }', async () => {
    const body = { discount: { code: 'SUMMER_28/07', value: 100000 } };

    await controller.create(1, body);

    expect(discounts.create).toHaveBeenCalledWith(1, body);
  });

  it('getOne truyen dung discountId + query fields', async () => {
    await controller.getOne(1, 1016875801, { fields: 'code,value' });

    expect(discounts.getOne).toHaveBeenCalledWith(1, 1016875801, {
      fields: 'code,value',
    });
  });

  it('enable/disable truyen dung discountId', async () => {
    await controller.enable(1, 1017981791);
    await controller.disable(1, 1017981791);

    expect(discounts.enable).toHaveBeenCalledWith(1, 1017981791);
    expect(discounts.disable).toHaveBeenCalledWith(1, 1017981791);
  });

  it('remove truyen dung discountId', async () => {
    await controller.remove(1, 1017981791);

    expect(discounts.remove).toHaveBeenCalledWith(1, 1017981791);
  });
});
