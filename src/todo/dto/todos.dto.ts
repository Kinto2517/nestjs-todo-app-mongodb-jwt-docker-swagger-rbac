import { ApiProperty } from '@nestjs/swagger';
import {
  IsDate,
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsString,
  Length,
} from 'class-validator';
import { TodosCategory } from '../enum';

export class TodosDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  title: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  description: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ type: String, format: 'date-time' })
  deadline: string;
  /*
  Should use the above example instead of this because THIS IS NOT WORKING: 
  @IsDate()
  @IsNotEmpty()
  @ApiProperty({ type: Date })
  deadline: Date;
  */

  @IsEnum(TodosCategory)
  @IsNotEmpty()
  @ApiProperty({ enum: TodosCategory, enumName: 'TodosCategory' })
  category: TodosCategory;
}
