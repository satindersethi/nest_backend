
import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Patch,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';

import { UserService } from './users.service';
import { PaginatedUsersResponseDto } from './dto/user.reponse.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/auth/decorator/roles.decorator';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Request } from 'express';

export interface AuthRequest extends Request {
  user: {
    email: string;
    role: string;
    sub: string;
  };
}


@ApiTags('Users')
@ApiBearerAuth('jwt')
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard) // 👈 protect whole controller
export class UserController {
  constructor(private readonly userService: UserService) {}

@Get()
@Roles('admin')
@ApiOperation({ summary: 'Get all users with pagination & search (Admin only)' })
@ApiQuery({
  name: 'page',
  required: false,
  example: 1,
})
@ApiQuery({
  name: 'limit',
  required: false,
  example: 10,
})
@ApiQuery({
  name: 'search',
  required: false,
  example: 'john',
  description: 'Search by name or email',
})
@ApiResponse({
  status: HttpStatus.OK,
  description: 'Users fetched successfully',
  type: PaginatedUsersResponseDto,
})
async getUsers(
  @Query('page') page = 1,
  @Query('limit') limit = 10,
  @Query('search') search?: string,
) {
  return this.userService.getAllUsers(
    Number(page),
    Number(limit),
    search,
  );
}


// ----------------------------------edit role--------------------------
@Patch('update_role')
@Roles('admin')
@ApiBearerAuth('jwt')
@ApiOperation({ summary: 'Update user role (Admin only)' })
async updateUserRole(
  @Body() dto: UpdateRoleDto,
  @Req() req: AuthRequest,
) {
  const adminEmail = req.user.email;
  return this.userService.updateUserRole(dto, adminEmail);
}

}
