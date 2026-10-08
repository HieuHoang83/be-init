import { Body, Controller, Get, Param, ParseIntPipe, Patch } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { UpdateShopSettingsDto } from './dto/update-shop-settings.dto';
import { ShopSettingsService } from './shop-settings.service';

@ApiTags('Shop Settings')
@Controller('shops/:orgId/settings')
export class ShopSettingsController {
  constructor(private readonly settings: ShopSettingsService) {}

  @Get()
  @ApiOperation({ summary: 'Get store settings for an organization' })
  get(@Param('orgId', ParseIntPipe) orgId: number) {
    return this.settings.get(orgId);
  }

  @Patch()
  @ApiOperation({ summary: 'Update store name and automatic repeat-order check setting' })
  update(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: UpdateShopSettingsDto,
  ) {
    return this.settings.update(orgId, body);
  }
}
