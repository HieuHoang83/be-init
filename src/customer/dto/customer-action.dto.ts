import { IsEmail, IsOptional, IsString } from 'class-validator';

/**
 * Du lieu tao khach tren Haravan.
 *
 * Gửi nguyên vẹn xuống `POST /customers.json`; Haravan tự kiểm tra và báo lỗi. Ở đây chỉ chặn
 * rõ ràng những lỗi chắc chắn sai để người dùng thấy ngay, thay vì để job chạy lên Haravan mới
 * fail.
 */
export class CreateCustomerBody {
  @IsOptional()
  @IsString()
  first_name?: string;

  @IsOptional()
  @IsString()
  last_name?: string;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  @IsEmail({}, { message: 'Email khong hop le' })
  email?: string;

  @IsOptional()
  @IsString()
  tags?: string;

  @IsOptional()
  @IsString()
  note?: string;

  @IsOptional()
  @IsString()
  state?: string;
}

/**
 * Du lieu sua khach. Cùng hình dạng với tạo khách vì Haravan dùng chung một tập trường cho
 * `PUT /customers/:id.json`; các truong khong gui di thi Haravan giu nguyen gia tri cu.
 */
export class UpdateCustomerBody extends CreateCustomerBody {}
