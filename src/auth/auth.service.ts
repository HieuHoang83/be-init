import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';
import { IUser } from 'src/interface/users.interface';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { genSaltSync, hashSync } from 'bcryptjs';
import { UserLoginDto } from './dto/login-user.dto';
import { UserService } from 'src/user/user.service';
import { UpdatePasswordDto } from 'src/user/dto/update-password.dto';
import { UserRegisterDto } from './dto/user-register.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  // Ham hash password
  private hashPassword(password: string): string {
    return hashSync(password, genSaltSync(10));
  }

  // Tao refresh token
  createRefreshToken(payload: object): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRE'),
    });
  }

  // Tao access token
  createAccessToken(payload: object): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRE'),
    });
  }

  // Dang ky user moi
  async registerUser(dto: UserRegisterDto) {
    const existing = await this.userService.findOneByPhone(dto.phone).catch(() => null);
    if (existing) {
      throw new BadRequestException('Phone number already registered');
    }

    const role = await this.userService.findRoleByName(dto.role);
    if (!role) {
      throw new BadRequestException(`Role "${dto.role}" does not exist`);
    }

    const user = await this.userService.create({
      name: dto.name,
      phone: dto.phone,
      password: this.hashPassword(dto.password),
      avatar: dto.avatar,
      roleId: role._id.toString(),
    });

    const { password, refreshToken, role: userRole, ...rest } = user.toObject();
    return { ...rest, role: userRole.name };
  }

  // Dang nhap user, tra ve user info + token
  async login(userLoginDto: UserLoginDto) {
    const { phone, password } = userLoginDto;

    const user = await this.userService.login(phone, password);

    const roleName = user.role?.name;

    const payload = {
      id: user._id.toString(),
      phone: user.phone,
      name: user.name,
      role: roleName,
    };

    const refresh_token = this.createRefreshToken(payload);
    const access_token = this.createAccessToken(payload);

    await this.userService.updateRefreshToken(payload.id, refresh_token);

    return {
      user: {
        id: payload.id,
        name: user.name,
        phone: user.phone,
        avatar: user.avatar,
        role: roleName,
      },
      token: { access_token, refresh_token },
    };
  }

  async validateUser(username: string, password: string) {
    return this.userService.login(username, password);
  }

  // Xu ly refresh token lay token moi
  verifyRefreshToken(refreshToken: string) {
    const secret = this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET');

    if (!secret) {
      throw new Error('JWT_REFRESH_TOKEN_SECRET is not set');
    }

    try {
      return this.jwtService.verify(refreshToken, { secret });
    } catch (error) {
      throw new BadRequestException('Invalid or expired refresh token');
    }
  }

  async processNewToken(refreshToken: string) {
    if (!refreshToken) {
      throw new BadRequestException('Refresh token is missing');
    }

    // Verify chu ky truoc, roi moi tim user
    this.verifyRefreshToken(refreshToken);

    const user = await this.userService.findOneByRefreshToken(refreshToken);
    if (!user) {
      throw new BadRequestException(
        'Refresh token not associated with any user',
      );
    }

    const payload = {
      sub: 'token login',
      iss: 'from server',
      id: user._id.toString(),
      name: user.name,
      phone: user.phone,
      role: user.role?.name,
    };

    return { access_token: this.createAccessToken(payload) };
  }

  // Dang xuat user
  async logout(user: IUser, response: Response) {
    await this.userService.updateRefreshToken(user.id, '');
    response.clearCookie('refresh_token');
    return true;
  }

  // Cap nhat mat khau user
  async updatePassword(userId: string, dto: UpdatePasswordDto) {
    await this.userService.updatePassword(userId, dto);
    return true;
  }
}
