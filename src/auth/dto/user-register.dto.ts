import {
  IsOptional,
  IsString,
  IsPhoneNumber,
  MinLength,
  IsIn,
} from 'class-validator';

export class UserRegisterDto {
  @IsString({ message: 'Name must be a string' })
  name: string;

  @IsPhoneNumber('VN', { message: 'Invalid phone number (VN format)' })
  phone: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  password: string;

  @IsOptional()
  @IsString({ message: 'Avatar must be a string (URL or path)' })
  avatar?: string;

  @IsString({ message: 'Role must be a string' })
  @IsIn(['Guest', 'Admin'], {
    message: 'Role must be either "Guest" or "Admin"',
  })
  role: string;
}
