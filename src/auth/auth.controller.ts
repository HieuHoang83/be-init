import {
  Post,
  UseGuards,
  Controller,
  Get,
  Body,
  Res,
  Req,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public, ResponseMessage, User } from 'src/decorators/customize';
import { LocalAuthGuard } from './local-auth.guard';
import { IUser } from 'src/interface/users.interface';
import { Request, Response } from 'express';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { UserLoginDto } from './dto/login-user.dto';
import { UpdatePasswordDto } from 'src/user/dto/update-password.dto';
import { Roles } from 'src/decorators/roles.decorator';
import { RolesGuard } from 'src/core/roles.guard';
import { GetPaginateInfo } from 'src/core/query.guard';
import { PaginateInfo } from 'src/interface/paginate.interface';
import { UserRegisterDto } from './dto/user-register.dto';
import { RefreshTokenDto } from './dto/refreshToken.dto';

@ApiTags('auth')
@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() dto: UserRegisterDto) {
    return this.authService.registerUser(dto);
  }
  @Public()
  @ResponseMessage('Login success')
  @Post('login')
  handleLogin(@Body() userLoginDto: UserLoginDto) {
    return this.authService.login(userLoginDto);
  }

  @Public()
  @Post('refresh-token')
  async refreshToken(@Body() dto: RefreshTokenDto) {
    return this.authService.processNewToken(dto.refreshToken);
  }
  @Patch('change-password')
  @ResponseMessage('Password updated successfully')
  async changePassword(@User() user: IUser, @Body() dto: UpdatePasswordDto) {
    return this.authService.updatePassword(user.id, dto);
  }
  @Get('logout')
  @ResponseMessage('Log out success')
  handleLogout(
    @User() user: IUser,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.logout(user, response);
  }
}
