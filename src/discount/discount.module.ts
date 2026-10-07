import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { DiscountController } from './discount.controller';
import { DiscountService } from './discount.service';
import { PromotionController } from './promotion.controller';

/** Module Discount + Promotion (Haravan Omni API `/com/discounts`, `/com/promotions`). */
@Module({
  imports: [ApiModule],
  controllers: [DiscountController, PromotionController],
  providers: [DiscountService],
})
export class DiscountModule {}
