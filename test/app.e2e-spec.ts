import { Test } from "@nestjs/testing";
import { AppModule } from "../src/app.module"
import { INestApplication, ValidationPipe } from "@nestjs/common";
import * as pactum from 'pactum';
import { AuthDto, LoginDto } from "../src/auth/dto";
import { TodoService } from "../src/todo/todo.service";
import { AuthService } from "../src/auth/auth.service";
import { TodosDto } from "../src/todo/dto";
import { TodosCategory } from "../src/todo/enum";

describe('App e2e', () => {

  let app: INestApplication;
  let todoService: TodoService;
  let authService: AuthService;

  beforeAll(async () => {
    const moduleRef =
      await Test.createTestingModule({
        imports: [AppModule],
      }).compile();
    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
    }))

    await app.init();
    await app.listen(3334);

    pactum.request.setBaseUrl('http://localhost:3334');

  });

  afterAll(() => {
    app.close();
  }
  );


  describe('Auth', () => {
    describe('Sign up', () => {

      it('should throw an error if email is not valid', () => {
        const dto: AuthDto = {
          name: 'Ers',
          surname: 'K',
          email: 'ersgmail.com',
          password: '123456',
        }
        return pactum
          .spec()
          .post('/auth/register')
          .withBody(dto)
          .expectStatus(400)
      });

      it('should create a new user', () => {
        const dto: AuthDto = {
          name: 'Ers',
          surname: 'K',
          email: 'ers@gmail.com',
          password: '123456',
        }
        return pactum
          .spec()
          .post('/auth/register')
          .withBody(dto)
          .expectStatus(201)
      });
      describe('Sign in', () => {
        it('should return a token', () => {
          const dto: LoginDto = {
            email: 'ers@gmail.com',
            password: '123456',
          }
          return pactum
            .spec()
            .post('/auth/login')
            .withBody(dto)
            .expectStatus(200)
            .stores('userAt', 'token');
        });
      });
    });
  });

  describe('User', () => {
    describe('Get user', () => {
      it('should return a user', () => {
        return pactum
          .spec()
          .get('/auth/me')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .stores('userId', '_id')
          .expectStatus(200)

      })

    });

  });

  describe('Todos', () => {
    describe('Get all empty todos', () => {
      it('should return todos', () => {
        return pactum
          .spec()
          .get('/todo/all')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .expectStatus(200)

      });
    })

    describe('Create todo', () => {
      it('should create a todo', () => {
        const dto: TodosDto = { title: 'Test todo', description: 'Test description', deadline: '2021-10-10', category: TodosCategory.WORK }
        return pactum
          .spec()
          .post('/todo/create')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .withBody(dto)
          .expectStatus(201)
          .stores('todoId', '_id')
      })
    });

    describe('Get one todo by id', () => {
      it('should return a todo', () => {
        return pactum
          .spec()
          .get('/todo/{id}')
          .withPathParams('id', '$S{todoId}')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .expectStatus(200)
          .inspect();

      })
    });

    describe('Update todo', () => {
      it('should update a todo', () => {
        const dto: TodosDto = { title: 'Test todo', description: 'Test description', deadline: '2021-10-10', category: TodosCategory.WORK }
        return pactum
          .spec()
          .patch('/todo/update/{id}')
          .withPathParams('id', '$S{todoId}')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .withBody(dto)
          .expectStatus(200)
      })
    });

    /* describe('Delete todo', () => {
      it('should delete a todo', () => {
        return pactum
          .spec()
          .delete('/todo/delete/{id}')
          .withPathParams('id', '$S{todoId}')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .expectStatus(200)
      })
    }); */

    describe('Delete user', () => {
      it('should delete a user', () => {
        return pactum
          .spec()
          .delete('/auth/delete')
          .withHeaders({
            Authorization: 'Bearer $S{userAt}'
          })
          .expectStatus(200)
          .inspect();
      })
    });

  });


});