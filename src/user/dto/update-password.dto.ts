import { IsString, MaxLength, MinLength } from 'class-validator';

export class UpdatePasswordDto {
  @IsString()
  @MinLength(6, { message: 'Old password must be at least 6 characters long' })
  @MaxLength(50, { message: 'Old password must not exceed 50 characters' })
  oldPassword: string;

  @IsString()
  @MinLength(6, { message: 'New password must be at least 6 characters long' })
  @MaxLength(50, { message: 'New password must not exceed 50 characters' })
  newPassword: string;
}
