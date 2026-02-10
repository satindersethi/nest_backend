import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh token issued during login',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..xxxxx',
  })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
