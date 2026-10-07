import { HaravanVariantController } from './haravan-variant.controller';
import { HaravanOmniService } from './haravan.service';

describe('HaravanVariantController', () => {
  const haravan = {
    getVariant: jest.fn(),
    updateProductVariant: jest.fn(),
  };
  const controller = new HaravanVariantController(
    haravan as unknown as HaravanOmniService,
  );

  beforeEach(() => {
    jest.resetAllMocks();
    haravan.updateProductVariant.mockResolvedValue({
      variant: { id: 1077703228 },
    });
  });

  it('getOne forward variantId va query', async () => {
    haravan.getVariant.mockResolvedValue({ variant: { id: 632910392 } });

    await controller.getOne(1, 632910392, { fields: 'sku,price' });

    expect(haravan.getVariant).toHaveBeenCalledWith(1, 632910392, {
      fields: 'sku,price',
    });
  });

  it('update gop id vao body.variant', async () => {
    await controller.update(1, 1077703228, {
      variant: { sku: 'CSSWWW', option1: 'M', price: 200000 },
    });

    expect(haravan.updateProductVariant).toHaveBeenCalledWith(1, 1077703228, {
      variant: {
        id: 1077703228,
        sku: 'CSSWWW',
        option1: 'M',
        price: 200000,
      },
    });
  });
});
