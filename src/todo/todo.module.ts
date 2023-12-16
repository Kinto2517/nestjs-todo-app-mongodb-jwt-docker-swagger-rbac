import { Module } from '@nestjs/common';
import { TodoController } from './todo.controller';
import { TodoService } from './todo.service';
import { MongooseModule } from '@nestjs/mongoose';
import { TodosSchema } from './schemas';
import { RolesGuard } from 'src/auth/guard/roles.guard';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'Todos', schema: TodosSchema }]),
  ],
  controllers: [TodoController],
  providers: [TodoService, RolesGuard],
})
export class TodoModule {}
