import {
  Body,
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  HaravanInventoryAdjustBody,
  ListHaravanInventoryLocationsQuery,
} from '../haravan-location/dto/location.dto';
import { HaravanInventoryService } from './haravan-inventory.service';

/**
 * Proxy Inventory Omni API (ton kho theo kho cua variant).
 * Scope Haravan: `com.read_inventories`, `com.write_inventories`.
 *
 * GET  /api/v1/haravan/:orgId/inventory_locations            <-> /com/inventory_locations.json
 * POST /api/v1/haravan/:orgId/inventories/adjustorset        <-> /com/inventories/adjustorset.json
 */
@ApiTags('Haravan Inventory')
@ApiBearerAuth('token')
@Controller('haravan/:orgId')
export class HaravanInventoryController {
  constructor(private readonly haravan: HaravanInventoryService) {}

  @Get('inventory_locations')
  @ApiOperation({
    summary: 'Ton kho theo kho (GET /com/inventory_locations.json)',
  })
  list(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: ListHaravanInventoryLocationsQuery,
  ) {
    return this.haravan.listInventoryLocations(orgId, query);
  }

  @Post('inventories/adjustorset')
  @ApiOperation({
    summary: 'Chinh sua ton kho (POST /com/inventories/adjustorset.json)',
  })
  adjust(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: HaravanInventoryAdjustBody,
  ) {
    return this.haravan.adjustInventory(orgId, body);
  }

  @Get('inventory_adjustments')
  @ApiOperation({
    summary: 'Danh sách điều chỉnh tồn kho (GET /com/inventories/adjustments.json)',
  })
  listAdjustments(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { limit?: string; page?: string; location_id?: string; since_id?: string },
  ) {
    return this.haravan.listInventoryAdjustments(orgId, query);
  }

  @Get('inventory_adjustments/count')
  @ApiOperation({
    summary: 'Đếm điều chỉnh tồn kho (GET /com/inventories/adjustments/count.json)',
  })
  countAdjustments(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { location_id?: string },
  ) {
    return this.haravan.countInventoryAdjustments(orgId, query);
  }

  @Get('inventory_adjustments/:adjustmentId')
  @ApiOperation({
    summary: 'Chi tiết điều chỉnh tồn kho (GET /com/inventories/adjustments/{id}.json)',
  })
  getAdjustment(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('adjustmentId', ParseIntPipe) adjustmentId: number,
  ) {
    return this.haravan.getInventoryAdjustment(orgId, adjustmentId);
  }

  @Get('purchase_receives')
  @ApiOperation({
    summary: 'Danh sách phiếu nhập (GET /com/v2/inventories/purchase_receives.json)',
  })
  listPurchaseReceives(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { limit?: string; page?: string },
  ) {
    return this.haravan.listPurchaseReceives(orgId, query);
  }

  @Get('purchase_receives/:purchaseReceiveId')
  @ApiOperation({
    summary: 'Chi tiết phiếu nhập (GET /com/v2/inventories/purchase_receives/{id}.json)',
  })
  getPurchaseReceive(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('purchaseReceiveId', ParseIntPipe) purchaseReceiveId: number,
  ) {
    return this.haravan.getPurchaseReceive(orgId, purchaseReceiveId);
  }

  @Get('purchase_orders')
  @ApiOperation({
    summary: 'Danh sách đơn đặt hàng nhập (GET /com/inventories/purchase_orders.json)',
  })
  listPurchaseOrders(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { limit?: string; page?: string },
  ) {
    return this.haravan.listPurchaseOrders(orgId, query);
  }

  @Get('purchase_orders/:purchaseId')
  @ApiOperation({
    summary: 'Chi tiết đơn đặt hàng nhập (GET /com/inventories/purchase_orders/{id}.json)',
  })
  getPurchaseOrder(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('purchaseId', ParseIntPipe) purchaseId: number,
  ) {
    return this.haravan.getPurchaseOrder(orgId, purchaseId);
  }

  @Get('purchase_returns')
  @ApiOperation({
    summary: 'Danh sách trả hàng nhập (GET /com/v2/inventories/purchase_returns.json)',
  })
  listPurchaseReturns(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { limit?: string; page?: string },
  ) {
    return this.haravan.listPurchaseReturns(orgId, query);
  }

  @Get('purchase_returns/:purchaseReturnId')
  @ApiOperation({
    summary: 'Chi tiết trả hàng nhập (GET /com/v2/inventories/purchase_returns/{id}.json)',
  })
  getPurchaseReturn(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('purchaseReturnId', ParseIntPipe) purchaseReturnId: number,
  ) {
    return this.haravan.getPurchaseReturn(orgId, purchaseReturnId);
  }

  @Get('inventory_transfers')
  @ApiOperation({
    summary: 'Danh sách điều chuyển (GET /com/inventories/transfers.json)',
  })
  listTransfers(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { limit?: string; page?: string; from_location_id?: string; to_location_id?: string; since_id?: string },
  ) {
    return this.haravan.listInventoryTransfers(orgId, query);
  }

  @Get('inventory_transfers/count')
  @ApiOperation({
    summary: 'Đếm điều chuyển (GET /com/inventories/transfers/count.json)',
  })
  countTransfers(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Query() query: { from_location_id?: string; to_location_id?: string },
  ) {
    return this.haravan.countInventoryTransfers(orgId, query);
  }

  @Get('inventory_transfers/:transferId')
  @ApiOperation({
    summary: 'Chi tiết điều chuyển (GET /com/inventorytransfer/detail/{id}.json)',
  })
  getTransfer(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('transferId', ParseIntPipe) transferId: number,
  ) {
    return this.haravan.getInventoryTransfer(orgId, transferId);
  }

  @Post('inventory_transfers')
  @ApiOperation({ summary: 'Tạo phiếu điều chuyển (POST /com/inventories/transfer.json)' })
  createTransfer(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Body() body: Record<string, unknown>,
  ) {
    return this.haravan.createInventoryTransfer(orgId, body);
  }

  @Post('inventory_transfers/:transferId/receive')
  @ApiOperation({
    summary: 'Nhận hàng điều chuyển (POST /com/inventories/transfer/{id}/receive.json)',
  })
  receiveTransfer(
    @Param('orgId', ParseIntPipe) orgId: number,
    @Param('transferId', ParseIntPipe) transferId: number,
    @Body() body: Record<string, unknown>,
  ) {
    return this.haravan.receiveInventoryTransfer(orgId, transferId, body);
  }
}
