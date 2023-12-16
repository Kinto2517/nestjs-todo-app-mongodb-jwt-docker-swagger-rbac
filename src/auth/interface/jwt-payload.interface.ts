import { Types } from 'mongoose';
import { Role } from '../enums/role.enum';

export interface IJwtPayload {
  userId: Types.ObjectId;
  roles: Role[];
}
