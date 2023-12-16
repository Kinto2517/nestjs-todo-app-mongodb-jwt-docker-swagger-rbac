Nestjs Todo App

* TodoController (+)
* Mongo(Mongoose) (+)
* Jwt Auth (+)
* Swagger (+)
* E2E Test (+)
* Role Based Auth (+)
* Microservice


INIT: 

```
nest new [project-name]
nest g service auth
nest g module  auth
nest g controller auth
auth/schemas -> index, tokens, users
```

CONFIG:
```
.env
npm i @nestjs/config
app.module -> configmodule.forroot -> isglobal true
```

MONGO - MONGOOSE:
npm i mongoose @nestjs/mongoose
MongooseModule.forRoot(process.env.MONGO_URI,
      {
        dbName: process.env.MONGO_NAME,
        auth: {
          username: process.env.MONGO_USER,
          password: process.env.MONGO_PASSWORD
        },
        directConnection: true,
      }),

SCHEMA:
```
@Schema({ versionKey: false, timestamps: true })
export class Token {
@Prop({ type: mongoose.Schema.Types.ObjectId })
userId : User;

@Prop({ required: true })
token : string;

}
```

PIPES (Transformation(PipeInt) - Validation):
npm i --save class-validator class-transformer

DTO: 
```
import { IsEmail, IsNotEmpty, IsString, Length } from "class-validator"

export class AuthDto {

@IsString()
@IsNotEmpty(
{ message: 'Name is required' }
)
name: string

@IsString()
@IsNotEmpty(
{ message: 'Surname is required' }
)
surname: string

@IsEmail()
@IsNotEmpty(
{ message: 'Email is required' }
)
email: string

@IsString()
@IsNotEmpty(
{ message: 'Password is required' }
)
@Length(6, 20, {
message: 'Password must be between 6 and 20 characters'
}
)
password: string

}
```

STRATEGY - JWT: 

```
npm i @nestjs/jwt @nestjs/passport @types/passport-jwt passport-jwt
```

```
interface IJwtPayload {
    userId: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    // INJECTMODEL SHOULD BE A PARAMETER OF CONSTRUCTOR 
    constructor(
        @InjectModel('Token') private readonly tokenModel: Model<Token>,
        @InjectModel('User') private readonly userModel: Model<User>,
    ) {
        super(
            //SIMPLE SUPER() TEMPLATE 
            {
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                ignoreExpiration: false,
                secretOrKey: process.env.JWT_SECRET_KEY
            }
        );
    }

    // WE CAN RETURN ANYTHING HERE - BETTER TO RETURN TOKEN OR USER
    async validate(payload: IJwtPayload): Promise<Token> {
        
        const userId = new Types.ObjectId(payload.userId);
        const token = await this.tokenModel.findOne({ userId }).select("-_id userId");
        const user = await this.userModel.findOne({ _id: userId });

        console.log("token ", token);
        console.log("user ", user);
        
        if (!token) {
            throw new UnauthorizedException();
        }

        return token;
    }
}
```

AUTH MODULE: 

```
// IMPORT MongooseModule Schemas and JwtModule.register
imports: [
    MongooseModule.forFeature([
      { name: 'User', schema: UserSchema },
      { name: 'Token', schema: TokenSchema }
    ]),
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: process.env.JWT_SECRET_KEY,
        signOptions: {
          expiresIn: process.env.JWT_EXPIRATION_TIME
        }
      })
    })
  ],
  //PROVIDE Services (@Injectables)
  providers: [
    AuthService,
    JwtStrategy
  ],
```

GLOBAL:
```
// Optional
app.setGlobalPrefix('api');
// Must add this line so our Validation in DTOs can work.
app.useGlobalPipes(new ValidationPipe())

```

AUTH CONTROLLER AND SERVICES:

```
constructor(private authService: AuthService) {}

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    register (@Body() dto: AuthDto) {
        return this.authService.register(dto);
    }

```

npm i bcrypt @types/bcrypt

//REGISTER METHOD
```
@Injectable()
export class AuthService {

    // IMPORT MODELS AS CONSTRUCTOR PARAMETER
    constructor(
        @InjectModel('User') private readonly userModel: Model<models.User>,
        @InjectModel('Token') private readonly tokenModel: Model<models.Token>,
    ) { }


    async register(dto: AuthDto) {
        const hashedPassword = await this.hashPassword(dto.password);
        const userCheck = await this.userModel.findOne({ email: dto.email });
        if (userCheck) {
            throw new BadRequestException('User already exists');
        }

        // YOU CAN SAVE THE USER EITHER WAY

        // (FIRST WAY)
        dto.password = hashedPassword;

        // (SECOND WAY) delete dto.password;

        const user = new this.userModel({
            ...dto,
            // (SECOND WAY) password: hashedPassword,
        });

        await user.save().catch((err) => {
            throw new BadRequestException("Error saving user");
        }
        );
        
        return user;
    }
    // HASHING PASSWORD
    async hashPassword(data: string) {
        return await bcrypt.hash(data, 10);
    }
}
```

//LOGIN 
```
async login(dto: LoginDto) {

        const { email, password } = dto;

        const user = await this.userModel.findOne({ email });

        if (!user) {
            throw new BadRequestException('Invalid Email');
        }

        const isPasswordMatches = await this.comparePassword(password, user.password);

        if (!isPasswordMatches) {
            throw new BadRequestException('Invalid Password');
        }

        const userId = user._id;

        const token = await this.generateToken({ userId });

        await this.tokenModel.findOneAndUpdate(
            { userId: new Types.ObjectId(String(userId))},
            { $set: { token } },    
            { upsert: true, new: true }
        )

        return { token };
    }
```

CONTROLLER SHOULD HAVE: 

```
@UseGuards(AuthGuard('jwt'))
for @Req() request.
```

SWAGGER:

npm install --save @nestjs/swagger

```
// Swagger
  const config = new DocumentBuilder()
    .setTitle('Todo App')
    .setDescription('Todo API with MongoDB, NestJS, JWT (RBAC), Swagger and Docker')
    .setVersion('1.0')
    .addTag('todos')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // Swagger DTO
  @IsString()
  @IsNotEmpty({ message: 'Surname is required' })
  @ApiProperty()
```

Delete User's Token and Todos with @InjectModel:
```
async deleteUser(userId: IJwtPayload) {
    await this.todoModel.deleteMany({ userId: userId });
    await this.tokenModel.findOneAndDelete({ userId: userId });
    await this.userModel.findByIdAndDelete(userId);

    return { message: 'User deleted' };
  }
```

E2E TEST: 
```
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
```


ROLE BASED AUTHENTICATION - IJWTPAYLOAD CHANGE:


Role Decorator: 
```
import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
```

Role Enum:

```
export enum Role {
    User = 'user',
    Admin = 'admin',
  }
```
Role Guard:

```
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '../enums/role.enum';
import { ROLES_KEY } from '../decorator/role.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    console.log(user);
    
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
```

* Guard Enum Decorator are mostly Copy Paste.

CHANGE IJWTPAYLOAD AND USER:

```
export interface IJwtPayload {
  userId: Types.ObjectId;
  roles: Role[];
}
```

User.schema: 

```
@Prop({ required: true, default: Role.User })
  roles: Role[];
```

Token.schema: 


```
@Prop({ required: true })
  roles: Role[];
```

Change Validate So We Can Select Roles:

```
 async validate(payload: IJwtPayload): Promise<Token> {
    const userId = new Types.ObjectId(payload.userId);

    const token = await this.tokenModel
      .findOne({ userId })
      .select('-_id userId roles');

    if (!token) {
      throw new UnauthorizedException();
    }

    return token;
  }
```

* Auth Service:

```
async getUserInfo(userId: IJwtPayload) {
    const user = await this.userModel
      .findById(userId)
      .select('name surname email roles');
    return user;
```

- LOGIN METHOD: 

```
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
    const payload: IJwtPayload = { userId, roles: user.roles }

    const token = await this.generateToken(payload);
    const roles = payload.roles;
    
    await this.tokenModel.findOneAndUpdate(
      { userId },
      { userId, token, roles },
      { upsert: true },
    );

    return { token };
  }
```
