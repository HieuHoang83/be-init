import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ApiError } from './api.service';
import { compactQuery, mapHaravanError } from './haravan.util';

describe('haravan.util', () => {
  it('compactQuery bo qua orgId va gia tri rong', () => {
    expect(
      compactQuery({
        orgId: 1,
        page: '1',
        vendor: '',
        sku: 'AO551',
        empty: null,
      }),
    ).toEqual({ page: '1', sku: 'AO551' });
  });

  it('mapHaravanError 404 -> NotFoundException', () => {
    expect(() => mapHaravanError(new ApiError(404, 'Not Found'))).toThrow(
      NotFoundException,
    );
  });

  it('mapHaravanError 422 -> BadRequestException', () => {
    expect(() =>
      mapHaravanError(new ApiError(422, 'invalid', { errors: ['title'] })),
    ).toThrow(BadRequestException);
  });
});
