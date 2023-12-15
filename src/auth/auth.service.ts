import { BadRequestException, Injectable } from '@nestjs/common';
import { Model, Types } from 'mongoose';
import * as models from './schemas';
import { InjectModel } from '@nestjs/mongoose';
import { AuthDto, LoginDto } from './dto';
import * as bcrypt from 'bcrypt';
import { IJwtPayload } from './interface';
import { JwtService } from '@nestjs/jwt';
import { Todos } from '../todo/schemas';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel('User') private readonly userModel: Model<models.User>,
    @InjectModel('Token') private readonly tokenModel: Model<models.Token>,
    @InjectModel('Todos') private readonly todoModel: Model<Todos>,
    private readonly jwtService: JwtService,
  ) { }

  async register(dto: AuthDto) {
    const hashedPassword = await this.hashPassword(dto.password);
    const userCheck = await this.userModel.findOne({ email: dto.email });

    if (userCheck) {
      throw new BadRequestException('User already exists');
    }

    dto.password = hashedPassword;

    const user = new this.userModel({
      ...dto,
    });

    await user.save().catch((err) => {
      throw new BadRequestException('Error saving user');
    });

    const userResponse = {
      id: user._id,
      name: user.name,
      surname: user.surname,
      email: user.email,
    };

    return userResponse;
  }

  async hashPassword(data: string) {
    return await bcrypt.hash(data, 10);
  }

  async login(dto: LoginDto) {
    const { email, password } = dto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new BadRequestException('Invalid Email');
    }

    const isPasswordMatches = await this.comparePassword(
      password,
      user.password,
    );

    if (!isPasswordMatches) {
      throw new BadRequestException('Invalid Password');
    }

    const userId = user._id;

    const token = await this.generateToken({ userId });

    await this.tokenModel.findOneAndUpdate(
      { userId: new Types.ObjectId(String(userId)) },
      { $set: { token } },
      { upsert: true, new: true },
    );

    return { token };
  }

  async deleteUser(userId: IJwtPayload) {
    await this.todoModel.deleteMany({ userId: userId });
    await this.tokenModel.findOneAndDelete({ userId: userId });
    await this.userModel.findByIdAndDelete(userId);

    return { message: 'User deleted' };
  }

  async getUserInfo(userId: IJwtPayload) {
    const user = await this.userModel
      .findById(userId)
      .select('name surname email');
    return user;
  }

  async generateToken(payload: IJwtPayload) {
    const token = await this.jwtService.sign(payload);
    return token;
  }

  async comparePassword(password: string, hashedPassword: string) {
    return await bcrypt.compare(password, hashedPassword);
  }

}
