import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Todos } from './schemas';
import { IJwtPayload } from '../auth/interface/index';
import { TodosDto } from './dto';
import { TodosUpdateDto } from './dto/todos-update.dto';

@Injectable()
export class TodoService {

    constructor(@InjectModel('Todos') private readonly todoModel: Model<Todos>) { }

    async getAllTodos(userId: IJwtPayload): Promise<Todos[]> {
        const todos = await this.todoModel.find({ userId: userId });

        if (!todos) {
            throw new NotFoundException('No todos found');
        }
        return todos;
    }

    async createTodos(userId: IJwtPayload, todosDto: TodosDto) {
        const todo = await this.todoModel.create({
            ...todosDto,
            userId: userId,
        });

        if (!todo) {
            throw new NotFoundException('Error creating todo');
        }

        return todo;
    }

    async updateTodos(
        userId: IJwtPayload,
        id: string,
        todosUpdateDto: TodosUpdateDto) {

        if (!todosUpdateDto) {
            throw new NotFoundException('No data sent');
        }

        const todo = await this.todoModel.findOneAndUpdate(
            { _id: id, userId: userId },
            { ...todosUpdateDto },
            { new: true },
        );

        if (!todo) {
            throw new NotFoundException('Todo not found');
        }

        return todo;
    }

    async deleteTodos(userId: IJwtPayload, id: any): Promise<{ message: string; }> {
        const todo = await this.todoModel.findOneAndDelete({ _id: id, userId: userId });

        return todo ? { message: 'Todo deleted' } : { message: 'Todo not found' };
    }

    async getTodoById(userId: IJwtPayload, todoId: string): Promise<Todos> {

        return await this.todoModel.findOne({ _id: todoId, userId: userId });
    }

    async deleteAllTodos(userId: IJwtPayload): Promise<{ message: string; }> {
        const todo = this.todoModel.deleteMany({ userId: userId });
        
        return await todo ? { message: 'Todos deleted' } : { message: 'Todos not found' };
    }

}
