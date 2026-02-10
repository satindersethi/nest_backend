import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger'; 

export class VerifyOtpDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    required: true,         
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;
  
  @ApiProperty({
    description: '6-digit numeric OTP code sent to your email',
    example: '483920',
    minLength: 6,
    maxLength: 6,
    required: true,
  })
  @IsString({ message: 'OTP must be a string' })
  @IsNotEmpty({ message: 'OTP is required' })
  @MinLength(6, { message: 'OTP must be exactly 6 digits' })
  @MaxLength(6, { message: 'OTP must be exactly 6 digits' })   
  @Matches(/^\d{6}$/, { message: 'OTP must contain exactly 6 digits' }) 
  otp: string;
}
