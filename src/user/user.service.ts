import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { compareSync, genSaltSync, hashSync } from 'bcryptjs';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Role, RoleDocument, User, UserDocument } from './user.entity';

/** Người dùng kèm vai trò đã tải, dùng cho đăng nhập và phản hồi API. */
export interface UserWithRole extends UserDocument {
  role: RoleDocument;
}

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
  ) {}

  private hashPassword(password: string): string {
    return hashSync(password, genSaltSync(10));
  }

  private checkPassword(password: string, hash: string): boolean {
    return compareSync(password, hash);
  }

  /** Mật khẩu mặc định không được truy vấn; cần thêm `+password` khi so sánh. */
  private findByIdRaw(id: string) {
    return this.userModel
      .findById(id)
      .select('+password')
      .populate('role')
      .exec();
  }

  async findOneById(id: string): Promise<UserWithRole> {
    const user = await this.userModel.findById(id).populate('role').exec();
    if (!user) {
      throw new BadRequestException('User not found');
    }
    return user as UserWithRole;
  }

  async findOneByPhone(phone: string): Promise<UserWithRole> {
    const user = await this.userModel
      .findOne({ phone })
      .populate('role')
      .exec();
    if (!user) {
      throw new BadRequestException('User not found');
    }
    return user as UserWithRole;
  }

  /** Tìm vai trò theo tên khi đăng ký người dùng mới. */
  async findRoleByName(name: string): Promise<RoleDocument | null> {
    return this.roleModel.findOne({ name }).exec();
  }

  async create(data: {
    name: string;
    phone: string;
    password: string;
    avatar?: string;
    roleId: string;
  }): Promise<UserWithRole> {
    const { roleId, ...userData } = data;
    return (await this.userModel
      .create({
        ...userData,
        role: roleId,
        password: this.hashPassword(data.password),
      })
      .then((u) => u.populate('role'))) as UserWithRole;
  }

  async login(phone: string, password: string): Promise<UserWithRole> {
    // Tải lại theo số điện thoại và lấy mật khẩu để so sánh.
    const user = await this.userModel
      .findOne({ phone })
      .select('+password')
      .populate('role')
      .exec();

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (!this.checkPassword(password, user.password)) {
      throw new BadRequestException('username or password is incorrect');
    }

    // Xóa mật khẩu trước khi trả kết quả.
    delete (user as unknown as { password?: string }).password;
    return user as UserWithRole;
  }

  async updateRefreshToken(userId: string, refreshToken: string | null) {
    return this.userModel
      .findByIdAndUpdate(userId, { refreshToken }, { new: true })
      .exec();
  }

  async updateUser(userId: string, updateUserDto: UpdateUserDto) {
    const user = await this.userModel
      .findByIdAndUpdate(userId, { $set: updateUserDto }, { new: true })
      .populate('role')
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Không trả mật khẩu cho phía gọi API.
    delete (user as unknown as { password?: string }).password;
    return user;
  }

  async getInfoByToken(userId: string) {
    const user = await this.userModel
      .findById(userId)
      .select('name phone avatar role')
      .populate('role', 'name')
      .lean()
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updatePassword(userId: string, dto: UpdatePasswordDto) {
    const user = await this.findByIdRaw(userId);
    if (!user) {
      throw new NotFoundException({ message: 'User not found' });
    }

    if (!this.checkPassword(dto.oldPassword, user.password)) {
      throw new BadRequestException('Old password is incorrect');
    }

    user.password = this.hashPassword(dto.newPassword);
    return user.save();
  }

  async remove(userId: string) {
    const user = await this.userModel.findByIdAndDelete(userId).exec();
    if (!user) {
      throw new NotFoundException({ message: 'User not found' });
    }
    return user;
  }

  async findOneByRefreshToken(token: string) {
    return this.userModel
      .findOne({ refreshToken: token })
      .select('+refreshToken')
      .populate('role')
      .exec();
  }

  async updateUserToken(userId: string, refreshToken: string) {
    return this.userModel
      .findByIdAndUpdate(userId, { refreshToken }, { new: true })
      .exec();
  }
}
