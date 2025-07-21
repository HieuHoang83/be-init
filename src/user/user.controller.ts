import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';

import { UpdateUserDto } from './dto/update-user.dto';
import { Public, ResponseMessage, User } from 'src/decorators/customize';
import { UserService } from './user.service';
import { ApiTags } from '@nestjs/swagger';
import { IUser } from 'src/interface/users.interface';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { Roles } from 'src/decorators/roles.decorator';
import { RolesGuard } from 'src/core/roles.guard';
import { PaginateInfo } from 'src/interface/paginate.interface';
import { GetPaginateInfo } from 'src/core/query.guard';

@ApiTags('users')
@Controller({ path: 'users', version: '1' })
export class UserController {
  constructor(private readonly userService: UserService) {}
  @Get('profile')
  async getProfile(@User() user: IUser) {
    return user;
  }
  @Delete(':id')
  @Roles('Super Admin', 'Assistant Admin')
  @UseGuards(RolesGuard)
  @ResponseMessage('Delete user')
  remove(@Param('id') id: string) {
    return this.userService.remove(id);
  }
  @Patch('update-info')
  async updateUserInfo(
    @User() user: IUser, // user đang đăng nhập
    @Body() dto: UpdateUserDto,
  ) {
    return this.userService.updateUser(user.id, dto);
  }
}
