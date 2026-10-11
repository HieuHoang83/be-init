import {
  parseCustomerSearch,
  phoneSuffix3,
  toSuffixRegex,
} from './customer-search.mapper';

describe('phoneSuffix3', () => {
  it('lay ba so cuoi cua so da chuan hoa', () => {
    expect(phoneSuffix3('0961277633')).toBe('633');
  });

  it('chuan hoa dinh quoc +84 ve dang dia phong truoc khi lay hau to', () => {
    expect(phoneSuffix3('84961277633')).toBe('633');
  });

  it('bo qua dau cach va ky tu la', () => {
    expect(phoneSuffix3('0961.277.633')).toBe('633');
  });

  it('tra undefined khi khong co so dien thoai hop le', () => {
    expect(phoneSuffix3(undefined)).toBeUndefined();
    expect(phoneSuffix3('123')).toBeUndefined();
  });
});

describe('parseCustomerSearch', () => {
  it('ba so nguyen duoc hieu la so cuoi', () => {
    expect(parseCustomerSearch('633')).toEqual({
      mode: 'phone_suffix',
      raw: '633',
      values: ['633'],
    });
  });

  it('cho phep nhieu nhom so cuoi', () => {
    const parsed = parseCustomerSearch('633, 888');
    expect(parsed.mode).toBe('phone_suffix');
    expect(parsed.mode === 'phone_suffix' && parsed.values).toEqual([
      '633',
      '888',
    ]);
  });

  it('loai bo so cuoi lap lai', () => {
    const parsed = parseCustomerSearch('633 633');
    expect(parsed.mode === 'phone_suffix' && parsed.values).toEqual(['633']);
  });

  it('tu bon so tro len duoc coi la so dien thoai tu dau', () => {
    expect(parseCustomerSearch('0961').mode).toBe('phone_prefix');
    expect(parseCustomerSearch('0961277633').mode).toBe('phone_prefix');
  });

  it('tu choi duoi ba so vi ket qua qua rong', () => {
    const parsed = parseCustomerSearch('63');
    expect(parsed.mode).toBe('invalid');
    expect(parsed.mode === 'invalid' && parsed.reason).toContain('3');
  });

  it('chu cai duoc tim theo ten hoac email', () => {
    expect(parseCustomerSearch('Nguyen Van A').mode).toBe('text');
  });

  it('chuoi rong hieu la xem tat ca', () => {
    expect(parseCustomerSearch('   ').mode).toBe('empty');
  });
});

describe('toSuffixRegex', () => {
  it('chi khop so dien thoai ket thuc bang gia tri da nhap', () => {
    const re = toSuffixRegex(['633']);
    expect('0961277633'.match(re)).not.toBeNull();
    // Cung chua `633` o giua nhung khong phai cuoi nen khong duoc khop.
    expect('0961633000'.match(re)).toBeNull();
  });

  it('hop lai nhieu nhom', () => {
    const re = toSuffixRegex(['633', '888']);
    expect('0961277633'.match(re)).not.toBeNull();
    expect('0912111888'.match(re)).not.toBeNull();
    expect('0912111777'.match(re)).toBeNull();
  });
});
