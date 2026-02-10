import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
  @ApiProperty({ example: 'Ajay Kumar' })
  name: string;

  @ApiProperty({ example: 'ajay@example.com' })
  email: string;

  @ApiProperty({ example: true })
  isVerified: boolean;

  @ApiProperty({ example: 'deactive' })
  status: string;

  @ApiProperty({ example: '2024-01-01T10:00:00.000Z' })
  createdAt: Date;

  @ApiProperty({ example: '2024-01-02T10:00:00.000Z' })
  updatedAt: Date;
}
