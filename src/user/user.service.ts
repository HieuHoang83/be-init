import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { compareSync, genSaltSync, hashSync } from 'bcryptjs';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { PaginateInfo } from 'src/interface/paginate.interface';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  private hashPassword(password: string): string {
    const salt = genSaltSync(10);
    return hashSync(password, salt);
  }

  private checkPassword(password: string, hash: string): boolean {
    return compareSync(password, hash);
  }

  async findOneById(id: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id },
      });
      if (!user) {
        throw new BadRequestException('User not found');
      }
      return user;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async findOneByPhone(phone: string) {
    try {
      return await this.prisma.user.findUnique({
        where: { phone: phone },
        include: {
          role: true, // include luôn role để lấy dữ liệu role
        },
      });
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async login(phone: string, password: string) {
    try {
      const user = await this.findOneByPhone(phone);
      if (!user) {
        throw new BadRequestException('User not found');
      }

      if (!this.checkPassword(password, user.password)) {
        throw new BadRequestException('username or password is incorrect');
      }
      delete user.password; // Xóa password trước khi trả về
      return user; // Trả về user (hoặc tạo JWT tại đây)
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  // ✅ Cập nhật thông tin user

  async updateRefreshToken(userId: string, refreshToken: string | null) {
    try {
      return await this.prisma.user.update({
        where: { id: userId },
        data: { refreshToken },
      });
    } catch (error) {
      throw new BadRequestException('Cập nhật refresh token thất bại');
    }
  }
  async updateUser(userId: string, updateUserDto: UpdateUserDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: updateUserDto,
    });

    delete updatedUser.password; // nếu có trường password, không trả về client
    return updatedUser;
  }

  async getInfoByToken(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        phone: true,
        avatar: true,
        role: {
          select: {
            name: true, // Lấy tên role
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }
  async updatePassword(userId: string, updatePasswordDto: UpdatePasswordDto) {
    try {
      // Kiểm tra nếu có người dùng với ID này
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException({ message: 'User not found' });
      }

      // Kiểm tra mật khẩu cũ

      if (!this.checkPassword(updatePasswordDto.oldPassword, user.password)) {
        throw new BadRequestException('Old password is incorrect');
      }
      // Cập nhật mật khẩu mới
      const hashedPassword = this.hashPassword(updatePasswordDto.newPassword);
      return await this.prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      });
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async remove(userId: string) {
    try {
      // Kiểm tra nếu có người dùng với ID này
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException({ message: 'User not found' });
      }

      // Xóa người dùng
      return await this.prisma.user.delete({
        where: { id: userId },
      });
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }
  async findOneByRefreshToken(token: string) {
    return this.prisma.user.findFirst({
      where: {
        refreshToken: token,
      },
    });
  }
  async updateUserToken(userId: string, refreshToken: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken },
    });
  }
}
