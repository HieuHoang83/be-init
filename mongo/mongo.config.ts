import { registerAs } from '@nestjs/config';

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

  const hasDbName = /^mongodb(\+srv)?:\/\/[^/]+\/[^/?]+/.test(uri);
  if (!hasDbName) {
    uri = uri.replace(/\/+$/, '') + `/${dbName}`;
  }

  return {
    uri,
    dbName,
    options: {
      dbName,
      retryWrites: true,
      w: 'majority',
      maxPoolSize: 20,
      serverSelectionTimeoutMS: 10000,
      autoIndex: process.env.NODE_ENV !== 'production',
    },
  };
});

export const MONGO_CONFIG_KEY = mongoConfig.KEY;
