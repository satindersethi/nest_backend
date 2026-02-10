import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class GoogleLoginDto {
  @ApiProperty({
    description: 'Firebase ID token received after Google login',
  })
  @IsString()
  @IsNotEmpty()
  idToken: string;
}
