nventory Adjustment
Version: 1.0

You can track inventory adjustment history in your shop. Alternatively, you can use it to change the available quantity of an inventory item at a single location.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Inventory Adjustment
The Haravan API lets you do the following with the Inventory Adjustment resource.

GET https://apis.haravan.com/com/inventories/adjustments.json
Retrieves a list of inventory adjustments.
GET https://apis.haravan.com/com/inventories/adjustments/count.json
Retrieve a count of the inventory adjustments.
GET https://apis.haravan.com/com/inventories/adjustments/{inventory_adjustment_id}.json
Retrieves single the inventory adjustments.
POST https://apis.haravan.com/com/inventories/adjustorset.json
Create an inventory adjustment.
Properties
id : number

"id": 1206854680

A unique identifier for the inventory adjustment.

created_at : string

"created_at": "2021-05-13T07:29:20.1Z"

The date and time (ISO 8601 format) when the inventory adjustment was created.

updated_at : string

"updated_at":"2021-05-13T07:29:20.808Z"

The date and time (ISO 8601 format) when the inventory adjustment was last updated.

adjust_number : string

"adjust_number":"IA100017"

The number of inventory adjustments.

tran_date : string

"tran_date": "2021-05-13T07:29:20.079Z"

The date and time (ISO 8601 format) when the inventory adjustment was changed.

location_id : number

"location_id": 963414

The ID of the inventory. You can get location information at the Location API.

type : string

"type": "adjust"

Valid values are: adjust, set.

adjust: add the new quantity with the old quantity.

set: override the new quantity with the old quantity.

if the type was not transferred, the default type is "adjust".

reason : array

"reason": "newproduct"

Valid values are: newproduct , returned , productionofgoods , damaged , shrinkage , promotion .

newproduct: New product. returned: Refund product. productionofgoods: Produce more products. damaged: Damanged. shrinkage: Loss. promotion: Promotion. transfer: Transfer.

if the type was not transferred, the default type is "newproduct".

total_quantity : number

"total_quantity": 50000

The quantity products of this inventory adjustment.

note : string

"note": "hàng hư hỏng do nhà sản xuất"

A note about the inventory adjustment.

total_cost : number

"total_cost": 150000000000.00

Total amount cost product of the inventory adjustment.

tags : string

"tags": "Hư hỏng"

Tags that the shop owner has attached to the inventory adjustment, formatted as a string of comma-separated values.

line_items : array

Details
Best supports 200 items for a request.

id: A unique identifier for the item in this line item.

product_id: A unique identifier for this product.

product_variant_id: A unique identifier for this product variant.

quantity: The number of the item for this product variant.

sku: A unique identifier for this product variant.

barcode: The barcode, UPC, or ISBN number for this product.

Retrieves a list of inventory adjustments.
GET
https://apis.haravan.com/com/inventories/adjustments.json

Retrieves a list of inventory adjustments. You can filter resources by params.

Parameters
limit

Limit of the result.

page

Page to show the result.

since_id

Restrict results to after the specified ID.

location_id

Filter result by the specified location ID.

Retrieve all of the resources of the inventory adjustment by page number. By default, the number of resources on the page is 50.

GET https://apis.haravan.com/com/inventories/adjustments.json?page=1
Details
Retrieve resources of the inventory adjustment by location id.

GET https://apis.haravan.com/com/inventories/adjustments.json?location_id=963414
Details
Retrieve a count of the inventory adjustments.
GET
https://apis.haravan.com/com/inventories/adjustments/count.json

Retrieve the count of resources of the inventory adjustment.
GET https://apis.haravan.com/com/inventories/adjustments/count.json
Details
Retrieves single the inventory adjustments.
GET
https://apis.haravan.com/com/inventories/adjustments/{adjustment_id}.json

Retrieves single the inventory adjustment.
GET https://apis.haravan.com/com/inventories/adjustments/1186432974.json
Details
Create an inventory adjustment.
POST
https://apis.haravan.com/com/inventories/adjustorset.json

Create an inventory adjustment.

POST https://apis.haravan.com/com/inventories/adjustorset.json

{
"inventory": {
"location_id": 84201,
"type": "adjust",
"reason": "newproduct",
"note": "update from api",
"line_items": [
{
"product_id": 1045244627,
"product_variant_id": 1099983464,
"quantity": 2
},
{
"product_id": 1054720936,
"product_variant_id": 1123302792,
"quantity": 3
}
]
}
}

Details
The API best supports arrays of 100 items per request.

The following table describes the possible responses from the Create an Inventory Adjustment API:

HTTP Status Description
201 Inventory adjustment completed successfully. The variants whose inventory was updated are returned in the response.
200 The system detected that the inventory quantity of the variant(s) has not changed, so no inventory update is required. This should be treated as a successful request.
422 The request contains invalid information.
429 The API call limit has been exceeded. The client should wait and retry.
5xx The system is temporarily unavailable or has encountered a server-side error. The client should wait and retry.
Connection Timeout The client did not receive a response within the configured timeout period. The client should wait and retry.
HTTP Status 422 – Unprocessable Entity
The API returns HTTP status 422 Unprocessable Entity when the request contains invalid data.
The system stops processing when invalid data is detected. A common cause is an invalid or non-existent product_id or variant_id.
For requests containing multiple variants, only one invalid variant is sufficient for the system to stop processing the request; the remaining variants are not checked or processed.
Invalid Inventory Location

HTTP/1.1 422 Unprocessable Entity
{
"errors": "Kho điều chỉnh không hợp lệ"
}

Invalid Product

HTTP/1.1 422 Unprocessable Entity
{
"errors": "Sản phẩm không hợp lệ"
}

Invalid Variant

HTTP/1.1 422 Unprocessable Entity
{
"errors": "Biến thể không hợp lệ"
}

Invalid Data

HTTP/1.1 422 Unprocessable Entity
{
"errors": "Dữ liệu không hợp lệ"
}

Invalid quantity : When type = "adjust", the quantity of each line_items must not be 0

HTTP/1.1 422 Unprocessable Entity
{
"errors": "Số lượng sản phẩm không hợp lệ"
}

Inventory Management Limitations
Inventory updates through the Inventory Adjustment API are currently not supported for the following product types:

Shops using Basic Inventory Management mode
Products managed by Lot/Date
Combo products
Products with fractional inventory quantities (decimal quantities)
For these product types, inventory adjustments should be performed through the Admin interface instead of using the Inventory Adjustment API.
Inventory Location Balance
Version: 1.0

An inventory item represents the physical goods available to be shipped to a customer. It holds essential information about the physical good, including its SKU and whether its inventory is tracked.

You can use the location id with variant id to query the inventory locations resources to retrieve inventory information.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Inventory Locations
The Haravan API lets you do the following with the Inventory Locations resource.

GET https://apis.haravan.com/com/inventory_locations.json?location_ids={location_ids}&variant_ids={variant_ids}
Retrieves a list of inventory items.
Properties
id : number

"id": 1206854680

The ID of the inventory item.

loc_id : number

"loc_id": 963414

product_id : number

"product_id": 1028183686

The ID of the product.

variant_id : number

"variant_id": 1064240649

The ID of the product variant.

qty_onhand : number

"qty_onhand": 0

The quantity of inventory items.

qty_commited : number

"qty_commited": 7

The quantity of inventory items ordered.

qty_incoming : number

"qty_incoming": 1

The quantity of inventory items ordered.

qty_available : number

"qty_available": 5

The quantity of inventory items available for sale.

updated_at : string

"updated_at": "2021-05-13T07:29:20.808Z"

The date and time (ISO 8601 format) when the inventory item was last updated.

Retrieves a list of inventory items
GET
https://apis.haravan.com/com/inventory_locations.json?location_ids={location_ids}&variant_ids={variant_ids}

Retrieves a list of inventory items.
Parameters
limit

Limit of the result.(default: 250, maximum: 250)

location_ids

Filter result by the comma-separated list of location ids. (maximum: 50)

vatiant_ids

Filter result by the comma-separated list of variant ids. (maximum: 50)

updated_at_min

Show inventory locations updated at or after date.

since_id

Show inventory locations after the specified ID.

order

Sort result by order id or order update_at order=id or order=updated_at.

direction

Sort result by the order direction=asc or direction=desc.

Retrieves a list of inventory items.

GET https://apis.haravan.com/com/inventory_locations.json?location_ids=1007284,963414&variant_ids=1061514767,1064240649
Details
Previous
Inventory Adjustment
Next
Inventory Purchase Order
What you can do with Inventory Locations
Properties
Retrieves a list of inventory items
Haravan
Home
Community
Facebook
Youtube
More
GitHub
Copyright
Inventory Purchase Order
You can use the Purchase Orders resource to document the sale of products and services to be delivered at a late date.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Purchase Orders
The Haravan API lets you do the following with the Purchase Orders resource.

GET https://apis.haravan.com/com/inventories/purchase_orders.json
Retrieves a list of purchase orders.
GET https://apis.haravan.com/com/inventories/purchase_orders/{purchase_id}.json
Retrieves single the purchase order.
Purchase Orders properties
id : number

"id": 1206854680

A unique identifier for the purchase order.

created_at : string

"created_at": "2021-05-13T07:29:20.1Z"

The date and time (ISO 8601 format) when the purchase order was created.

notes : string

"notes": "nhập hàng tháng 11"

An optional note that a shop owner can attach to the purchase order.

status : string

"status": "Chưa nhận hàng"

"Chưa nhận hàng": has not received the product.

"Hoàn thành": has received the product.

tran_date : string

"tran_date": "2021-07-27T03:29:32Z"

Expected date of delivery.The date and time (ISO 8601 format).

completed_at : string

"completed_at": "2021-07-27T03:29:32Z"

Received date of delivery.The date and time (ISO 8601 format).

closed_at : string

"closed_at": "2014-12-18T00:00:00-05:00"

Purchase order closing date.The date and time (ISO 8601 format).

ref_number : string

"ref_number": "IN_3007"

Reference number of the purchase order.

supplier : string

"supplier": "Khác"

Supplier of the purchase order.

location : json

Details
line_item : json

Details
Retrieves a list of purchase orders.
GET
https://apis.haravan.com/com/inventories/purchase_orders.json
Retrieves a list of purchase orders.

Parameters
limit

Limit of the result.

page

Page to show the result.

Retrieves a list of purchase orders by page number. By default, the number of resources on the page is 50.

GET https://apis.haravan.com/com/inventories/purchase_orders?page=1
Details
Retrieves single the purchase order.
GET
https://apis.haravan.com/com/inventories/purchase_orders/{purchase_id}.json
Retrieves single the purchase order.

GET https://apis.haravan.com/com/inventories/purchase_orders/1000355305.json
Details
Previous
Inventory Location Balance
Next
Inventory Purchase Receive
What you can do with Purchase Orders
Purchase Orders properties
Retrieves a list of purchase orders.
Retrieves single the purchase order.
Haravan
Home
Community
Facebook
Youtube
More
GitHub
Copyright © 2026 Haravan.
Inventory Purchase Receive
You can use the Purchase Receives resource to document the sale of products and services to be delivered at a late date.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Purchase Receives
The Haravan API lets you do the following with the Purchase Receives resource.

GET https://apis.haravan.com/com/v2/inventories/purchase_receives.json
Retrieves a list of purchase receives.
GET https://apis.haravan.com/com/v2/inventories/purchase_receives/{purchase_receive_id}.json
Retrieves single the purchase receive.
Purchase Receives properties
id : number

"id": 1001004628

A unique identifier for the purchase receive.

receive_number : string

"receive_number": "IR1000000007"

The number of the purchase receive.

ref_number : string

"ref_number": "#732000"

Reference number of the purchase receive.

ref_purchase_order_id : number

"ref_purchase_order_id": null

Reference purchase order number of the purchase receive.

tags: string

"tags": "tagsational, tag1, tag2, tag3"

Tags are additional short descriptors formatted as a string of comma-separated values. For example, if an article has three tags: tag1, tag2, tag3.

created_at : string

"created_at": "2022-08-25T05:15:12.917Z"

The date and time (ISO 8601 format) when the purchase receive was created.

updated_at : string

"updated_at": "2022-09-05T02:27:46.779Z"

The date and time (ISO 8601 format) when the purchase receive was updated.

received_at : string

"received_at": "2022-08-25T05:15:12.917Z"

The date and time (ISO 8601 format) when the purchase receive was received.

notes : string

"notes": "Notes"

An optional note that a shop owner can attach to the purchase receive.

status : string

"status": "Đã nhập hàng"

Nháp: draft.

Đã nhập hàng: has received the product.

Đã xuất trả: has returned the product.

Đã hủy: has canceled the product.

total : number

"total": 1100

Total quantity of purchase receive.

total_cost : number

"total_cost": 1080100

Total cost of purchase receive.

supplier : json

Details
location : json

Details
line_items : json

Details
Retrieves a list of purchase receives.
GET
https://apis.haravan.com/com/v2/inventories/purchase_receives.json

Retrieves a list of purchase receives. You can filter resources by params.

Parameters
limit

Limit of the result.

page

Page to show the result.

Retrieve all of the resources of the purchase receives by page number. By default, the number of resources on the page is 50.

GET https://apis.haravan.com/com/v2/inventories/purchase_receives.json?page=1
Details
Retrieves single the purchase receive.
GET
https://apis.haravan.com/com/v2/inventories/purchase_receives/{purchase_receive_id}.json
Retrieves single the purchase receive.

GET https://apis.haravan.com/com/v2/inventories/purchase_receives/1001004628.json
Details
Previous
Inventory Purchase Order
Next
Inventory Purchase Return
What you can do with Purchase Receives
Purchase Receives properties
Retrieves a list of purchase receives.
Retrieves single the purchase receive.
Haravan
Home
Community
Facebook
Youtube
More
GitHub
Copyright © 2026 Haravan.
Inventory Purchase Return
You can use the Purchase Receives resource to document the sale of products and services to be delivered at a late date.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Purchase Return
The Haravan API lets you do the following with the Purchase Receives resource.

GET https://apis.haravan.com/com/v2/inventories/purchase_returns.json
Retrieves a list of purchase returns.
GET https://apis.haravan.com/com/v2/inventories/purchase_returns/{purchase_return_id}.json
Retrieves single the purchase return.
Purchase Return properties
id : number

"id": 1001004628

A unique identifier for the purchase return.

return_number : string

"return_number": "IR1000000007"

The number of the purchase return.

ref_number : string

"ref_number": "#732000"

Reference number of the purchase return.

ref_receive_id : number

"ref_receive_id": null

Reference purchase order number of the purchase return.

tags: string

"tags": "tagsational, tag1, tag2, tag3"

Tags are additional short descriptors formatted as a string of comma-separated values. For example, if an article has three tags: tag1, tag2, tag3.

created_at : string

"created_at": "2022-08-25T05:15:12.917Z"

The date and time (ISO 8601 format) when the purchase return was created.

updated_at : string

"updated_at": "2022-09-05T02:27:46.779Z"

The date and time (ISO 8601 format) when the purchase return was updated.

returned_at : string

"returned_at": "2022-08-25T05:15:12.917Z"

The date and time (ISO 8601 format) when the purchase return was returned.

notes : string

"notes": "Notes"

An optional note that a shop owner can attach to the purchase return.

status : string

"status": "Đã xuất trả"

Nháp: draft.

Đã nhập hàng: has received the product.

Đã xuất trả: has returned the product.

Đã hủy: has canceled the product.

total : number

"total": 1100

Total quantity of purchase receive.

total_cost : number

"total_cost": 1080100

Total cost of purchase receive.

supplier : json

Details
location : json

Details
line_items : json

Details
Retrieves a list of purchase returns.
GET
https://apis.haravan.com/com/v2/inventories/purchase_returns.json

Retrieves a list of purchase returns. You can filter resources by params.

Parameters
limit

Limit of the result.

page

Page to show the result.

Retrieve all of the resources of the purchase receives by page number. By default, the number of resources on the page is 50.

GET https://apis.haravan.com/com/v2/inventories/purchase_returns.json?page=1
Details
Retrieves single the purchase return.
GET
https://apis.haravan.com/com/v2/inventories/purchase_returns/{purchase_return_id}.json
Retrieves single the purchase receive.

GET https://apis.haravan.com/com/v2/inventories/purchase_returns/1001004833.json
Details
Previous
Inventory Purchase Receive
Next
Inventory Transfer
What you can do with Purchase Return
Purchase Return properties
Retrieves a list of purchase returns.
Retrieves single the purchase return.
Haravan
Home
Community
Facebook
Youtube
More
GitHub
Copyright © 2026 Haravan.
nventory Transfer
Version: 1.0

You can track inventory transfer history in your shop. Alternatively, you can use it to transfer the available quantity of an inventory item from a location to another location.

Authenticated access scopes: com.read_inventories, com.write_inventories

What you can do with Inventory Transfer
The Haravan API lets you do the following with the Inventory Transfer resource.

GET https://apis.haravan.com/com/inventories/transfers.json
Retrieves a list of inventory transfers
GET https://apis.haravan.com/com/inventories/transfers/count.json
Retrieve a count of the inventory transfer
GET https://apis.haravan.com/com/inventorytransfer/detail/{inventory_tranfer_id}.json
Retrieves single the inventory transfer
POST https://apis.haravan.com/com/inventories/transfer.json
Create an inventory transfer
POST https://apis.haravan.com/com/inventories/transfer/{inventory_tranfer_id}/receive.json
Receive an inventory transfer
Properties
id : number

"id": 1001030743

A unique identifier for the inventory transfer.

created_at : string

"created_at": "2021-05-13T07:29:20.1Z"

The date and time (ISO 8601 format) when the inventory adjustment was created.

updated_at : string

"updated_at":"2021-05-13T07:29:20.808Z"

The date and time (ISO 8601 format) when the inventory adjustment was last updated.

transfer_number : string

"transfer_number":"IT100001"

The number of inventory transfers.

tran_date : string

"tran_date": "2021-05-13T07:29:20.079Z"

The date and time (ISO 8601 format) when the inventory adjustment was changed.

from_loc_id : number

"from_loc_id": 963414

The ID of the inventory transfer. You can get location information at the Location API.

to_loc_id : number

"to_loc_id": 1007284

The ID of the inventory received. You can get location information at the location API.

total : number

"total": 10

Amount quantity products of inventory transfer.

reason : string

"reason": "newproduct"

Valid values are: newproduct , returned , productionofgoods , damaged , shrinkage , promotion.

newproduct: New product. returned: Refund p. productionofgoods: Produce more products. damaged: Damanged. shrinkage: Loss. promotion: Promotion. transfer: Transfer.

if the type was not transferred, the default type is "newproduct".

user_id : number

"user_id": 200000493247

A unique identifier of the user. Can you get user information at User API.

note : string

"note": "hàng hư hỏng do nhà sản xuất"

A note about the inventory transfer.

tags : string

"tags": "Hư hỏng"

Tags that the shop owner has attached to the inventory transfer, formatted as a string of comma-separated values.

line_items : array

Details
id: A unique identifier for the item in this line item.

product_id: A unique identifier for this product.

product_variant_id: A unique identifier for this product variant.

quantity: The number of the item for this product variant.

sku: A unique identifier for this product variant.

Retrieves a list of inventory transfers
GET
https://apis.haravan.com/com/inventories/transfers.json

Retrieves a list of inventory transfers. You can filter resources by params.
Params
limit

Limit of the result.

page

Page to show the result.

since_id

Restrict results to after the specified ID.

from_location_id

Filter result by the specified transfer location ID.

to_location_id

Filter result by the specified receive location ID.

Retrieve all of the resources of the inventory transfers by page number. By default, the number of resources on the page is 50.

GET https://apis.haravan.com/com/inventories/transfers.json?page=1
Details
Retrieve resources of the inventory adjustment by transfer location id or receive location id.

GET https://apis.haravan.com/com/inventories/transfers.json?from_location_id=963414
Details
Retrieve a count of the inventory transfer
GET
https://apis.haravan.com/com/inventories/transfers/count.json

Retrieve a count of the inventory transfer.
GET https://apis.haravan.com/com/inventories/transfers/count.json
Details
Retrieves single the inventory transfer
GET
https://apis.haravan.com/com/inventorytransfer/detail/{inventory_tranfer_id}.json

Retrieves single the inventory transfer by ID.
GET https://apis.haravan.com/com/inventorytransfer/detail/1001030743.json
Details
Create an inventory transfer
POST
https://apis.haravan.com/com/inventories/transfer.json

Create an inventory transfer.
POST https://apis.haravan.com/com/inventories/transfer.json
{
"transfer": {
"from_loc_id": 479749,
"to_loc_id": 479754,
"note": "chuyển kho",
"reason": "newproduct",
"received_at": "2017-06-09T17:00:00Z",
"user_id": 3,
"line_items": [
{
"product_id": 10000260270,
"product_variant_id": 101021136,
"quantity": 1
}
]
}
}

Details
Receive an inventory transfer
POST
https://apis.haravan.com/com/inventories/transfer/{inventory_tranfer_id}/receive.json

Receive an inventory transfer.
POST https://apis.haravan.com/com/inventories/transfer/1000100351/receive.json
{
"transfer": {
"user_id": 3
}
}

Details
Previous
Inventory Purchase Return
Next
Metafield
What you can do with Inventory Transfer
Properties
Retrieves a list of inventory transfers
Retrieve a count of the inventory transfer
Retrieves single the inventory transfer
Create an inventory transfer
Receive an inventory transfer
Haravan
Home
Community
Facebook
Youtube
More
GitHub
Copy
