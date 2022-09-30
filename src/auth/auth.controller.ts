import {
  Body,
  Controller,
  Post,
  Get,
  UseGuards,
  Param,
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Roles } from './decorators/roles.decorator';
import { LoginDto } from './dto/login.dto';
import { SignUpDto } from './dto/sign-up.dto';
import { JwtAuthGuard } from './guards/jwt.guard';
import { RolesGuard } from './guards/roles.guard';
import { SignUpPipe } from './pipes/sign-up.pipe';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body(SignUpPipe) newUser: SignUpDto) {
    return this.authService.signup(newUser);
  }

  @Post('login')
  login(@Body() user: LoginDto) {
    return this.authService.login(user);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getMe(@Param('username') username: string) {
    return this.authService.getMe(username);
  }

  @Delete('delete')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  delteUser(@Body('username') username: string) {
    console.log('delete user ' + username);
    return this.authService.deleteUser(username);
  }
}
