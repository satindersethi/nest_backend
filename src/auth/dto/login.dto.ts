import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'bs@yopmail.com',
    required: true,
  })
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePass123',
    required: true,
  })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

export class ForceLoginDto {
  @ApiProperty({ example: 'bs@yopmail.com' })
  @IsEmail()
  email: string;
}
