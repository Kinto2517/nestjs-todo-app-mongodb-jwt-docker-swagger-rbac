import { Types } from 'mongoose';

export interface IJwtPayload {
  userId: Types.ObjectId;
}
