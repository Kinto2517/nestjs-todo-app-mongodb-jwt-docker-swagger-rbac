import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Model, Types } from 'mongoose';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Token, User } from '../schemas';
import { InjectModel } from '@nestjs/mongoose';
import { IJwtPayload } from '../interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @InjectModel('Token') private readonly tokenModel: Model<Token>,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET_KEY,
    });
  }

  async validate(payload: IJwtPayload): Promise<Token> {
    const userId = new Types.ObjectId(payload.userId);

    const token = await this.tokenModel
      .findOne({ userId })
      .select('-_id userId roles');

    if (!token) {
      throw new UnauthorizedException();
    }

    return token;
  }
}
