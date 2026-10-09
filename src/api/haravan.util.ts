import {
  BadGatewayException,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiError } from './api.service';

export function compactQuery(
  query: Record<string, unknown>,
  omit: string[] = [],
): Record<string, string | number> {
  const skipped = new Set(['orgId', ...omit]);
  const params: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(query)) {
    if (
      skipped.has(key) ||
      value === undefined ||
      value === null ||
      value === ''
    ) {
      continue;
    }
    if (typeof value === 'string' || typeof value === 'number') {
      params[key] = value;
    }
  }
  return params;
}

export function mapHaravanError(error: unknown): never {
  if (error instanceof ApiError) {
    if (error.statusCode === 401 || error.statusCode === 403) {
      throw new UnauthorizedException(error.message);
    }
    if (error.statusCode === 404) {
      throw new NotFoundException(error.message);
    }
    if (error.statusCode >= 400 && error.statusCode < 500) {
      throw new BadRequestException({
        message: error.message,
        errors: error.body,
      });
    }
    throw new BadGatewayException(error.message);
  }
  throw error;
}
