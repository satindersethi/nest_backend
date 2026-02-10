import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsEnum } from 'class-validator';

export enum UserRole {
  user = 'user',
  admin = 'admin',
}

export class UpdateRoleDto {
  @ApiProperty({
    example: 'bs@yopmail.com',
    description: 'Email of the user whose role will be updated',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    enum: UserRole,
    example: UserRole.admin,
    description: 'New role to assign',
  })
  @IsEnum(UserRole)
  role: UserRole;
}
