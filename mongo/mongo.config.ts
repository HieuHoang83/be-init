import { registerAs } from '@nestjs/config';

/**
 * Cau hinh MongoDB.
 *
 * Uu tien theo thu tu:
 *  1. MONGODB_URI         - neu biet san URI day du (co ca database name)
 *  2. MONGODB_USERNAME +
 *     MONGODB_PASSWORD + MONGODB_CLUSTER - ghep URI SRV tu may
 *  3. fallback localhost:27017
 *
 * `atlas-credentials.env` (sinh ra boi MongoDB Atlas) cung cap MONGODB_USERNAME /
 * MONGODB_PASSWORD / MONGODB_URI nen duoc nap qua envFilePath o ConfigModule.
 */
export interface MongoConfig {
  uri: string;
  dbName: string;
  options: Record<string, unknown>;
}

export const mongoConfig = registerAs('mongo', (): MongoConfig => {
  const dbName =
    process.env.MONGODB_DB_NAME || process.env.MONGODB_DATABASE || 'be_init';

  let uri = process.env.MONGODB_URI?.trim();

  if (!uri) {
    const user = process.env.MONGODB_USERNAME;
    const pass = process.env.MONGODB_PASSWORD;
    const cluster = process.env.MONGODB_CLUSTER;

    if (user && pass && cluster) {
      const credentials = `${encodeURIComponent(user)}:${encodeURIComponent(
        pass,
      )}`;
      uri = `mongodb+srv://${credentials}@${cluster}`;
    }
  }

  if (!uri) {
    uri = `mongodb://localhost:27017/${dbName}`;
  }

  // URI tu Atlas onboarding thuong khong co ten database -> append vao
  const hasDbName = /^mongodb(\+srv)?:\/\/[^/]+\/[^/?]+/.test(uri);
  if (!hasDbName) {
    uri = uri.replace(/\/+$/, '') + `/${dbName}`;
  }

  return {
    uri,
    dbName,
    options: {
      dbName,
      // Atlas yeu cau cac tuy chon nay de connection duoc on dinh
      retryWrites: true,
      w: 'majority',
      maxPoolSize: 20,
      serverSelectionTimeoutMS: 10000,
      autoIndex: process.env.NODE_ENV !== 'production',
    },
  };
});

/** Key dung de configService.get() trong module */
export const MONGO_CONFIG_KEY = mongoConfig.KEY;
