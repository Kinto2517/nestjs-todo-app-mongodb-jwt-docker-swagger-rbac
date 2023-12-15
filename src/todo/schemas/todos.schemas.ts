import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { User } from '../../auth/schemas';
import { TodosCategory } from '../enum';

export type TodosSchema = mongoose.HydratedDocument<Todos>;

@Schema({ versionKey: false, timestamps: true })
export class Todos {
  @Prop({ type: mongoose.Schema.Types.ObjectId })
  userId: User;

  @Prop({ required: true })
  title: string;

  @Prop({ required: true })
  description: string;

  @Prop({ required: true })
  deadline: Date;

  @Prop({ required: true })
  category: TodosCategory;
}

export const TodosSchema = SchemaFactory.createForClass(Todos);
