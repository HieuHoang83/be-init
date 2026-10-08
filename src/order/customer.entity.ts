import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/** Thông tin khách được tổng hợp theo từng shop. */
@Schema({ collection: 'customers', timestamps: true })
export class Customer {
  @Prop({ required: true, index: true })
  orgId!: number;

  /** ID khách trên Haravan. */
  @Prop({ index: true })
  haravanCustomerId?: number;

  /** Số điện thoại đã chuẩn hóa. */
  @Prop({ index: true })
  phone?: string;

  @Prop({ index: true })
  email?: string;

  @Prop()
  firstName?: string;
  @Prop()
  lastName?: string;

  /** Tên đầy đủ của khách. */
  @Prop() fullName?: string;

  @Prop()
  state?: string;
  @Prop({ default: false })
  verifiedEmail?: boolean;

  /** Tổng số đơn theo Haravan. */
  @Prop({ default: 0 })
  haravanOrdersCount?: number;

  @Prop({ default: 0 })
  haravanTotalSpent?: number;

  @Prop() lastOrderId?: number;
  @Prop() lastOrderName?: string;

  /** Số đơn đã lưu trong BE. */
  @Prop({ default: 0 })
  beOrderCount?: number;

  @Prop({ default: 0 })
  beTotalSpent?: number;

  /** ID các đơn của khách. */
  @Prop({ type: [Number], default: [] })
  orderIds?: number[];

  @Prop() firstSeenAt?: Date;
  @Prop() lastSeenAt?: Date;

  /** Nguồn cập nhật thông tin khách gần nhất. */
  @Prop() infoSourceOrderId?: number;
  @Prop() infoSourceTopic?: string;
}

export type CustomerDocument = HydratedDocument<Customer>;
export const CustomerSchema = SchemaFactory.createForClass(Customer);

/** Khóa duy nhất theo shop và thông tin nhận diện khách. */
CustomerSchema.index(
  { orgId: 1, haravanCustomerId: 1 },
  { sparse: true, unique: true },
);
// Dùng partial index thay cho `sparse`: `sparse` chỉ bỏ qua document thiếu
// field, nhưng bỏ qua field = null. Khách đặt hàng không có email/điện thoại sẽ
// ghi `email: null`, khiến E11000 duplicate key (orgId + null) và job chết.
// partialFilterExpression giữ được tính duy nhất cho giá trị thật.
CustomerSchema.index(
  { orgId: 1, phone: 1 },
  {
    unique: true,
    partialFilterExpression: { phone: { $type: 'string' } },
  },
);
CustomerSchema.index(
  { orgId: 1, email: 1 },
  {
    unique: true,
    partialFilterExpression: { email: { $type: 'string' } },
  },
);
CustomerSchema.index({ orgId: 1, lastSeenAt: -1 });
