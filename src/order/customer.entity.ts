import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/**
 * Khach hang cua 1 shop, gom lai tu moi don de biet day la khach cu hay moi.
 *
 * Ly do can bang rieng (khong chi doc `orders`):
 *  - `orders/create` co the THIEU ten/sdt, chi `orders/updated` moi co du
 *  - nhieu don cung 1 khach -> dem nhanh, khong can query
 *  - khoa tim bang sdt, vi `email` thuong null o don COD
 */
@Schema({ collection: 'customers', timestamps: true })
export class Customer {
  @Prop({ required: true, index: true })
  orgId!: number;

  /** Id khach o Harovan. Co gia tri o payload moi. */
  @Prop({ index: true })
  haravanCustomerId?: number;

  /** Sdt chuan hoa (bỏ khoang trắng, dấu +, số 0 dau) - khoa so sanh chinh */
  @Prop({ index: true })
  phone?: string;

  @Prop({ index: true })
  email?: string;

  @Prop()
  firstName?: string;
  @Prop()
  lastName?: string;

  /** Ten day du, uu tien shipping_address.name */
  @Prop() fullName?: string;

  @Prop()
  state?: string;
  @Prop({ default: false })
  verifiedEmail?: boolean;

  /** So don Haravan da gom TAT CA (da ke don hien tai) */
  @Prop({ default: 0 })
  haravanOrdersCount?: number;

  @Prop({ default: 0 })
  haravanTotalSpent?: number;

  @Prop() lastOrderId?: number;
  @Prop() lastOrderName?: string;

  /** So don BE da luu cho khach nay */
  @Prop({ default: 0 })
  beOrderCount?: number;

  @Prop({ default: 0 })
  beTotalSpent?: number;

  /** Danh sach don cua khach, dung de doi chieu khi can */
  @Prop({ type: [Number], default: [] })
  orderIds?: number[];

  @Prop() firstSeenAt?: Date;
  @Prop() lastSeenAt?: Date;

  /** Don nao moi nhat dua thong tin khach vao - giup truy nguon */
  @Prop() infoSourceOrderId?: number;
  @Prop() infoSourceTopic?: string;
}

export type CustomerDocument = HydratedDocument<Customer>;
export const CustomerSchema = SchemaFactory.createForClass(Customer);

/**
 * Khoa duy nhat: uu tien id Haravan, khong co thi dung sdt.
 * Regex de `email` null khong tao nhieu ban ghi trung.
 */
CustomerSchema.index(
  { orgId: 1, haravanCustomerId: 1 },
  { sparse: true, unique: true },
);
CustomerSchema.index({ orgId: 1, phone: 1 }, { sparse: true, unique: true });
CustomerSchema.index({ orgId: 1, email: 1 }, { sparse: true, unique: true });
CustomerSchema.index({ orgId: 1, lastSeenAt: -1 });
