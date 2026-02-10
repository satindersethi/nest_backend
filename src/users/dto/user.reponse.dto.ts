import { ApiProperty } from '@nestjs/swagger';
import { UserDto } from './user-response.dto';

export class PaginatedUsersResponseDto {
  @ApiProperty({ example: 'deactive' })
  status: string;

  @ApiProperty({ type: [UserDto] })
  users: UserDto[];

  @ApiProperty({ example: 120 })
  total: number;

  @ApiProperty({ example: 1 })
  page: number;

  @ApiProperty({ example: 10 })
  limit: number;
}
