import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { hash, verify } from 'argon2';
import { Roles } from './constants/roles.enum';
import { LoginDto } from './dto/login.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { User } from './interfaces/user.interface';

@Injectable()
export class AuthService {
  private users: User[] = [];

  constructor(private readonly jwtService: JwtService) {
    this.users.push(
      {
        username: 'john',
        password: 'changeme',
        firstName: 'John',
        lastName: 'Doe',
        roles: [Roles.USER, Roles.ADMIN],
      },
      {
        username: 'chris',
        password: 'secret',
        firstName: 'Chris',
        lastName: 'Smith',
        roles: [Roles.USER],
      },
      {
        username: 'maria',
        password: 'guess',
        firstName: 'Maria',
        lastName: 'Jones',
        roles: [Roles.ADMIN],
      },
    );
  }

  async findUser(username: string): Promise<User | undefined> {
    const user = this.users.find(
      (user) => user.username === username,
    );
    return user;
  }

  async createAccessToken(username: string) {
    const token = await this.jwtService.signAsync(
      { sub: username },
      {
        expiresIn: '10m',
        secret: process.env.JWT_SECRET || 'secret',
      },
    );
    return token;
  }

  async signup(newUser: SignUpDto): Promise<any> {
    if (await this.findUser(newUser.username))
      throw new ConflictException('Username already exists');

    const hashedPassword: string = await hash(
      String(newUser.password),
    );

    this.users.push({
      username: newUser.username,
      password: hashedPassword,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      roles: [Roles.ADMIN],
    });

    const token = await this.createAccessToken(newUser.username);

    return { access_token: token };
  }

  async login(user: LoginDto): Promise<any> {
    try {
      const foundUser = await this.findUser(user.username);

      if (!foundUser) throw new Error('No user found');

      const isPasswordValid = await verify(
        foundUser.password,
        `${user.password}`,
      );

      if (!isPasswordValid) throw new Error('Invalid password');

      const token = await this.createAccessToken(foundUser.username);

      return { access_token: token };
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async getMe(username: string): Promise<any> {
    const user = await this.findUser(username);
    return {
      ...user,
      status: 'active',
    };
  }

  async deleteUser(username: string): Promise<any> {
    const user = await this.findUser(username);
    if (!user) throw new Error('No user found with ' + username);
    this.users = this.users.filter(
      (user) => user.username !== username,
    );
    return { status: 'deleted' };
  }
}
