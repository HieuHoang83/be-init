import { PromotionController } from './promotion.controller';
import { DiscountService } from './discount.service';

describe('PromotionController', () => {
  const discounts = {
    listPromotions: jest.fn(),
    getPromotion: jest.fn(),
    createPromotion: jest.fn(),
    removePromotion: jest.fn(),
    enable: jest.fn(),
    disable: jest.fn(),
  };
  const controller = new PromotionController(
    discounts as unknown as DiscountService,
  );

  beforeEach(() => {
    jest.resetAllMocks();
    discounts.listPromotions.mockResolvedValue({ promotions: [] });
    discounts.getPromotion.mockResolvedValue({ promotion: { id: 1024173229 } });
    discounts.createPromotion.mockResolvedValue({
      promotion: { id: 1024177200 },
    });
    discounts.removePromotion.mockResolvedValue({});
    discounts.enable.mockResolvedValue({ discount: {} });
    discounts.disable.mockResolvedValue({ discount: {} });
  });

  it('list forward query limit/page/code', async () => {
    await controller.list(1, { page: '1', code: 'SUMMER' });

    expect(discounts.listPromotions).toHaveBeenCalledWith(1, {
      page: '1',
      code: 'SUMMER',
    });
  });

  it('create forward body { promotion }', async () => {
    const body = { promotion: { name: 'Happy new year', value: 10000 } };

    await controller.create(1, body);

    expect(discounts.createPromotion).toHaveBeenCalledWith(1, body);
  });

  it('getOne truyen dung promotionId', async () => {
    await controller.getOne(1, 1024173229, {});

    expect(discounts.getPromotion).toHaveBeenCalledWith(1, 1024173229, {});
  });

  it('enable/disable dung endpoint /discounts/{id}/...', async () => {
    await controller.enable(1, 1024177200);
    await controller.disable(1, 1017981791);

    expect(discounts.enable).toHaveBeenCalledWith(1, 1024177200);
    expect(discounts.disable).toHaveBeenCalledWith(1, 1017981791);
  });

  it('remove truyen dung promotionId', async () => {
    await controller.remove(1, 1024177200);

    expect(discounts.removePromotion).toHaveBeenCalledWith(1, 1024177200);
  });
});
