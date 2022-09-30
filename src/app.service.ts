import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  indexPage(): any {
    return {
      message: "Hello, World"
    }
  }
  getHello(): string {
    return 'Hello World!';
  }
}
