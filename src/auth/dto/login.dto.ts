import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty({ message: 'Email is required' })
  @ApiProperty()
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  @Length(6, 20, {
    message: 'Password must be between 6 and 20 characters',
  })
  @ApiProperty()
  password: string;
}
