import {
    Body,
    Controller,
    Delete,
    Get,
    Param,
    Patch,
    Post,
    Req,
    Request,
    UseGuards,
} from '@nestjs/common';
import { TodoService } from './todo.service';
import { ApiBearerAuth } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { TodosDto } from './dto';
import { Todos } from './schemas';
import { TodosUpdateDto } from './dto/todos-update.dto';

@Controller('todo')
export class TodoController {
    constructor(private todoService: TodoService) { }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Get('all')
    getTodos(@Req() req): Promise<Todos[]> {
        const userId = req.user.userId;
        return this.todoService.getAllTodos(userId);
    }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Get('/:id')
    getTodoById(@Request() req, @Param('id') todoId: string): Promise<Todos> {
        const userId = req.user.userId;
        return this.todoService.getTodoById(userId, todoId);
    }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Post('create')
    createTodo(@Request() req, @Body() todosDto: TodosDto): Promise<Todos> {
        const userId = req.user.userId;
        return this.todoService.createTodos(userId, todosDto);
    }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Patch('update/:id')
    updateTodo(
        @Request() req,
        @Param('id') todoId: string,
        @Body() todosUpdateDto: TodosUpdateDto,
    ): Promise<Todos> {
        const userId = req.user.userId;

        return this.todoService.updateTodos(userId, todoId, todosUpdateDto);
    }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Delete('delete/:id')
    deleteTodo(
        @Request() req,
        @Param('id') todoId: string,
    ): Promise<{ message: string }> {
        const userId = req.user.userId;

        return this.todoService.deleteTodos(userId, todoId);
    }

    @ApiBearerAuth()
    @UseGuards(AuthGuard('jwt'))
    @Delete('delete-all')
    deleteAllTodos(@Request() req): Promise<{ message: string }> {
        const userId = req.user.userId;

        return this.todoService.deleteAllTodos(userId);
    }
}
