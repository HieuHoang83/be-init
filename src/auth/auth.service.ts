import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';
import { IUser } from 'src/interface/users.interface';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import ms from 'ms';
import { genSaltSync, hashSync, compareSync } from 'bcryptjs';
import { UserLoginDto } from './dto/login-user.dto';
import { UserService } from 'src/user/user.service';
import { UpdatePasswordDto } from 'src/user/dto/update-password.dto';
import { PaginateInfo } from 'src/interface/paginate.interface';
import { UserRegisterDto } from './dto/user-register.dto';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  // Hàm hash password
  private hashPassword(password: string): string {
    const salt = genSaltSync(10);
    return hashSync(password, salt);
  }

  // Tạo refresh token
  createRefreshToken(payload: any): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRE'),
    });
  }

  // Tạo access token
  createAccessToken(payload: any): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRE'),
    });
  }

  // Đăng ký user mới
  async registerUser(dto: UserRegisterDto) {
    // Kiểm tra số điện thoại đã tồn tại chưa
    const existingUser = await this.prisma.user.findUnique({
      where: { phone: dto.phone },
    });

    if (existingUser) {
      throw new BadRequestException('Phone number already registered');
    }

    // Tìm role theo tên
    const role = await this.prisma.role.findUnique({
      where: { name: dto.role },
    });

    if (!role) {
      throw new BadRequestException(`Role "${dto.role}" does not exist`);
    }

    const hashedPassword = this.hashPassword(dto.password);

    // Tạo người dùng mới
    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        phone: dto.phone,
        password: hashedPassword,
        avatar: dto.avatar,
        roleId: role.id,
      },
    });

    delete user.password; // Không trả về password cho client
    return user;
  }

  // Đăng nhập user, trả về user info + token
  async login(userLoginDto: UserLoginDto) {
    console.log('Login attempt with:', userLoginDto);
    const { phone, password } = userLoginDto;

    // Gọi service xử lý login
    const user = await this.userService.login(phone, password);

    // Tạo payload token
    const payload = {
      id: user.id,
      phone: user.phone,
      name: user.name,
      role: user.role.name,
    };

    const refresh_token = this.createRefreshToken(payload);
    const access_token = this.createAccessToken(payload);
    await this.userService.updateRefreshToken(user.id, refresh_token);
    // Không trả về password
    const { id, refreshToken, roleId, ...userClean } = user;

    return {
      user: {
        ...userClean,
        role: user.role.name,
      },
      token: {
        access_token,
        refresh_token,
      },
    };
  }

  async validateUser(username: string, password: string) {
    return await this.userService.login(username, password);
  }

  // Xử lý refresh token lấy token mới
  verifyRefreshToken(refreshToken: string) {
    const secret = this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET');

    if (!secret) {
      throw new Error('JWT_REFRESH_TOKEN_SECRET is not set');
    }

    try {
      const decoded = this.jwtService.verify(refreshToken, { secret });
      console.log('Decoded refresh token:', decoded);
      return decoded;
    } catch (error) {
      throw new BadRequestException('Invalid or expired refresh token');
    }
  }
  async processNewToken(refreshToken: string) {
    if (!refreshToken) {
      throw new BadRequestException('Refresh token is missing');
    }

    const decoded = this.verifyRefreshToken(refreshToken);

    // Tìm user theo refresh token
    const user = await this.prisma.user.findFirst({
      where: { refreshToken },
      select: {
        id: true,
        name: true,
        phone: true,
        avatar: true,
        role: {
          select: {
            name: true,
          },
        },
      },
    });

    if (!user) {
      throw new BadRequestException(
        'Refresh token not associated with any user',
      );
    }

    const payload = {
      sub: 'token login',
      iss: 'from server',
      id: user.id,
      name: user.name,
      phone: user.phone,
      role: user.role.name,
    };

    return {
      access_token: this.createAccessToken(payload),
    };
  }

  // Đăng xuất user
  async logout(user: IUser, response: Response) {
    await this.userService.updateRefreshToken(user.id, '');
    response.clearCookie('refresh_token');
    return true;
  }

  // Cập nhật mật khẩu user
  async updatePassword(userId: string, updatePasswordDto: UpdatePasswordDto) {
    await this.userService.updatePassword(userId, updatePasswordDto);
    return true;
  }
}
