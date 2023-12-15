import { Module } from '@nestjs/common';
import { TodoController } from './todo.controller';
import { TodoService } from './todo.service';
import { MongooseModule } from '@nestjs/mongoose';
import { TodosSchema } from './schemas';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'Todos', schema: TodosSchema }]),
  ],
  controllers: [TodoController],
  providers: [TodoService],
})
export class TodoModule {}
