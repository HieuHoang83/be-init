import { HaravanProductController } from './haravan-product.controller';
import { HaravanOmniService } from './haravan.service';

describe('HaravanProductController', () => {
  const haravan = {
    listProducts: jest.fn(),
    createProduct: jest.fn(),
    updateProduct: jest.fn(),
    createProductVariant: jest.fn(),
    deleteProductVariant: jest.fn(),
  };
  const controller = new HaravanProductController(
    haravan as unknown as HaravanOmniService,
  );

  beforeEach(() => {
    jest.resetAllMocks();
    haravan.updateProduct.mockResolvedValue({ product: { id: 632910392 } });
  });

  it('update gop id vao body.product', async () => {
    await controller.update(1, 632910392, {
      product: { tags: "Barnes & Noble, John's Fav" },
    });

    expect(haravan.updateProduct).toHaveBeenCalledWith(1, 632910392, {
      product: { id: 632910392, tags: "Barnes & Noble, John's Fav" },
    });
  });

  it('createVariant forward body { variant } theo product', async () => {
    const body = { variant: { sku: 'CSSWWW', option1: 'S', price: 100000 } };
    haravan.createProductVariant.mockResolvedValue({ variant: { id: 1 } });

    await controller.createVariant(1, 1034037268, body);

    expect(haravan.createProductVariant).toHaveBeenCalledWith(
      1,
      1034037268,
      body,
    );
  });

  it('removeVariant truyen dung productId va variantId', async () => {
    haravan.deleteProductVariant.mockResolvedValue({});

    await controller.removeVariant(1, 1034037268, 1077703228);

    expect(haravan.deleteProductVariant).toHaveBeenCalledWith(
      1,
      1034037268,
      1077703228,
    );
  });
});
