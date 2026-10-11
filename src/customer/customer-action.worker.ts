import {
  BadRequestException,
  Injectable,
  Logger,
  OnModuleInit,
} from '@nestjs/common';
import { Job, JobQueue, JOB_NAMES, NonRetryableError } from '../queue/queue.service';
import { ApiError } from '../api/api.service';
import { HaravanCustomerService } from '../haravan-customer/haravan-customer.service';
import {
  CustomerSyncService,
  HaravanCustomerPayload,
} from './customer-sync.service';

/** Noi dung cong viec cho thao tac tao/sua khach len Haravan. */
export interface CustomerActionJobPayload {
  orgId: number;
  /** Bat buoc voi `customer.update`. */
  haravanCustomerId?: number;
  actor?: string;
  /** Than request gui lai cho Haravan, giong nhung controller nhan tu FE. */
  body?: Record<string, unknown>;
}

/**
 * Worker cho thao tac tao/sua khach hang tren Haravan.
 *
 * Controller chi day cong viec vao hang doi roi tra `202 Accepted` kem `jobId`, nho do so request
 * song song len Haravan duoc gioi han boi `HARAVAN_QUEUE_CONCURRENCY` va FE theo doi ket qua
 * that bang cach poll trang thai job.
 *
 * Worker ghi MongoDB ngay tu response cua Haravan de nguoi dung thay du lieu da doi ngay, sau do
 * Haravan con gui webhook `customers/create|update` va nhung du lieu do cung quy ve mot ham ghi
 * nen chay hai lan van khong sinh ban ghi trung.
 */
@Injectable()
export class CustomerActionWorker implements OnModuleInit {
  private readonly logger = new Logger(CustomerActionWorker.name);

  constructor(
    private readonly jobQueue: JobQueue,
    private readonly haravan: HaravanCustomerService,
    private readonly sync: CustomerSyncService,
  ) {}

  /**
   * Loi 4xx tu Haravan (sai du lieu, khach khong ton tai) thi thu lai cung vo nghia.
   * 429 va 5xx van duoc retry.
   */
  private rethrow(error: unknown): never {
    const status = (error as ApiError)?.statusCode;
    if (status && status >= 400 && status < 500 && status !== 429) {
      throw new NonRetryableError((error as Error).message);
    }
    const nestStatus = (error as { getStatus?: () => number })?.getStatus?.();
    if (nestStatus && nestStatus >= 400 && nestStatus < 500) {
      throw new NonRetryableError((error as Error).message);
    }
    throw error;
  }

  onModuleInit(): void {
    this.jobQueue.registerHandler<CustomerActionJobPayload>(
      JOB_NAMES.CUSTOMER_CREATE,
      (job) => this.handleCreate(job),
    );
    this.jobQueue.registerHandler<CustomerActionJobPayload>(
      JOB_NAMES.CUSTOMER_UPDATE,
      (job) => this.handleUpdate(job),
    );
  }

  private async handleCreate(job: Job<CustomerActionJobPayload>): Promise<void> {
    const { orgId, body, actor } = job.payload;
    if (!body) throw new BadRequestException('Thieu du lieu tao khach hang');

    const response = await this.haravan
      .createCustomer(orgId, body)
      .catch((error: unknown) => this.rethrow(error));
    const customer = extractCustomer(response);

    const result = await this.sync.upsertFromHaravan(
      orgId,
      customer,
      'job.create',
    );

    this.logger.log(
      `Da tao khach ${customer.id} tren Haravan (org ${orgId}, ` +
        `${result.created ? 'tao moi' : 'cap nhat'} local)`,
    );
    job.result = JSON.stringify({
      message: `Da tao khach ${label(customer)} tren Haravan`,
      haravanCustomerId: customer.id,
    });
  }

  private async handleUpdate(job: Job<CustomerActionJobPayload>): Promise<void> {
    const { orgId, haravanCustomerId, body, actor } = job.payload;
    if (!haravanCustomerId) {
      throw new BadRequestException('Thieu ma khach hang can sua');
    }

    const response = await this.haravan
      .updateCustomer(orgId, haravanCustomerId, body ?? {})
      .catch((error: unknown) => this.rethrow(error));
    const customer = extractCustomer(response);

    await this.sync.upsertFromHaravan(orgId, customer, 'job.update');

    this.logger.log(
      `Da sua khach ${haravanCustomerId} tren Haravan (org ${orgId})`,
    );
    job.result = JSON.stringify({
      message: `Da cap nhat khach ${label(customer)} tren Haravan`,
      haravanCustomerId,
    });
  }
}

/** Haravan tra `{ customer: {...} }`; mot so endpoint tra thang object khach. */
function extractCustomer(response: unknown): HaravanCustomerPayload {
  const body = (response ?? {}) as Record<string, unknown>;
  const customer = (body['customer'] ?? body) as HaravanCustomerPayload;
  return customer ?? {};
}

function label(customer: HaravanCustomerPayload): string {
  const name = [customer.first_name, customer.last_name].filter(Boolean).join(' ');
  return name.trim() || customer.email || customer.phone || `#${customer.id}`;
}
