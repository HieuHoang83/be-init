// user.entity.ts
export class User {
    id: string;
    name: string;
    email: string;
    password: string;
    createdAt: Date;
    phone: string;
    refreshToken?: string;
    notifications?: any[]; // Will be replaced with Notify[] when that entity is created
  }