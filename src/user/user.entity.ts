import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Schema as MongooseSchema } from 'mongoose';

@Schema({ collection: 'roles', timestamps: true })
export class Role {
  @Prop({ required: true, unique: true })
  name!: string;
}
export type RoleDocument = HydratedDocument<Role>;

export const RoleSchema = SchemaFactory.createForClass(Role);

@Schema({ collection: 'users', timestamps: true })
export class User {
  @Prop({ required: true, trim: true })
  name!: string;

  /** So dien thoai la dinh danh, khong trung */
  @Prop({ required: true, unique: true })
  phone!: string;

  @Prop({ required: true, select: false })
  password!: string;

  @Prop()
  avatar?: string;

  @Prop({ index: true, sparse: true })
  refreshToken?: string;

  @Prop({ type: MongooseSchema.Types.ObjectId, ref: Role.name, required: true })
  role!: RoleDocument | Role;
}
export type UserDocument = HydratedDocument<User>;

export const UserSchema = SchemaFactory.createForClass(User);

// So dien thoai la dinh danh -> unique index
UserSchema.index({ phone: 1 }, { unique: true });
UserSchema.index({ refreshToken: 1 }, { sparse: true });
