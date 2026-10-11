import {
  BadRequestException,
  Inject,
  Injectable,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { appConfig } from '../config';

/** Du lieu can nho giua `/login` va `/callback`. */
export interface LoginState {
  /** Chong replay id_token trong Authorization Code Flow. */
  nonce: string;
  /** PKCE code_verifier phai giu lai de doi code lay token. */
  codeVerifier: string;
  /** Trang web frontend muon quay ve sau khi dang nhap xong. */
  redirectUri?: string;
  createdAt: number;
}

/** Session da tao xong, frontend doi bang POST /haravan/auth/session. */
export interface LoginTicket {
  userId: string;
  createdAt: number;
}

/**
 * Luu state/nonce/PKCE va ticket trong RAM cua mot tien trinh.
 *
 * `state` va `ticket` deu la gia tri ngau nhien va chi dung mot lan, nen
 * khong can ghi ra dia/dung database. Do lai khac mot lan server thi frontend
 * phai bat dau lai luong dang nhap (khong ton tai gi giua cac instance).
 */
@Injectable()
export class HaravanAuthStateService implements OnModuleDestroy {
  private readonly states = new Map<string, LoginState>();
  private readonly tickets = new Map<string, LoginTicket>();
  private readonly ttlMs: number;
  private readonly timer: NodeJS.Timeout;

  constructor(@Inject(appConfig.KEY) config: ConfigType<typeof appConfig>) {
    this.ttlMs = config.openid.stateTtlMs;

    // Don rac giac han, khong giu tien trinh alive.
    this.timer = setInterval(() => this.prune(), 60_000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    clearInterval(this.timer);
  }

  saveState(state: string, data: Omit<LoginState, 'createdAt'>): void {
    this.states.set(state, { ...data, createdAt: Date.now() });
  }

  /**
   * Lay va xoa state. Tra loi 400 khi thieu hoac het han: chinh la dau hieu
   * cua request khong phai do chinh trinh duyet vua nguoi dung gui.
   */
  consumeState(state: string | undefined): LoginState {
    if (!state) {
      throw new BadRequestException(
        'Thieu tham so `state`. Hay mo lai link dang nhap tu dau.',
      );
    }

    const saved = this.states.get(state);
    this.states.delete(state);

    if (!saved || Date.now() - saved.createdAt > this.ttlMs) {
      throw new BadRequestException(
        'State khong hop le hoac da het han. Hay mo lai link dang nhap tu dau.',
      );
    }

    return saved;
  }

  /** Cap ma doi token mot lan cho frontend sau khi callback thanh cong. */
  issueTicket(userId: string): string {
    const ticket = randomUUID();
    this.tickets.set(ticket, { userId, createdAt: Date.now() });
    return ticket;
  }

  /** Lay va xoa ticket, phai khop `state`. */
  consumeTicket(ticket: string | undefined): LoginTicket {
    if (!ticket) {
      throw new BadRequestException('Thieu ma `ticket`.');
    }

    const saved = this.tickets.get(ticket);
    this.tickets.delete(ticket);

    if (!saved || Date.now() - saved.createdAt > this.ttlMs) {
      throw new BadRequestException(
        'Ticket khong hop le hoac da het han. Hay dang nhap lai.',
      );
    }

    return saved;
  }

  private prune(): void {
    const now = Date.now();

    for (const [key, value] of this.states) {
      if (now - value.createdAt > this.ttlMs) this.states.delete(key);
    }

    for (const [key, value] of this.tickets) {
      if (now - value.createdAt > this.ttlMs) this.tickets.delete(key);
    }
  }
}
