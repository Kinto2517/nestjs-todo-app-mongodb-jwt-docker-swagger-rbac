import { ApiProperty } from '@nestjs/swagger';
import {
  IsDate,
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
} from 'class-validator';
import { TodosCategory } from '../enum';

export class TodosUpdateDto {
  @IsString()
  @IsOptional()
  @ApiProperty()
  title?: string;

  @IsString()
  @IsOptional()
  @ApiProperty()
  description?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ type: String, format: 'date-time' })
  deadline?: string;

  @IsEnum(TodosCategory)
  @IsOptional()
  @ApiProperty({ enum: TodosCategory, enumName: 'TodosCategory' })
  category?: TodosCategory;
}
