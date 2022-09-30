import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
} from '@nestjs/common';
import { SignUpDto } from '../dto/sign-up.dto';

@Injectable()
export class SignUpPipe implements PipeTransform {
  transform(value: unknown, _metadata: ArgumentMetadata) {
    const errors: string[] = [];

    if (!this.valueHasPassAndConfirmPass(value))
      throw new BadRequestException('Invalid payload');

    if (value.password !== value.confirmPassword)
      errors.push('Password and confirm password must match');

    if (errors.length > 0)
      throw new BadRequestException(errors.join(', '));
    
    return value;
  }

  private valueHasPassAndConfirmPass(
    value: unknown,
  ): value is SignUpDto {
    return (
      typeof value === 'object' &&
      value !== null &&
      'password' in value &&
      'confirmPassword' in value
    );
  }
}
