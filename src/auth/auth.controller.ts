import {
  Controller,
  Post,
  Get,
  Req,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import type { Request } from 'express';

import { AuthService } from './auth.service';
import { VerifyOtpDto } from '../otp/dto/verify-otp.dto';
import { ResendOtpDto } from 'src/otp/dto/resend-otp';
import { ForceLoginDto, LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Public } from 'src/common/decorators/public.decoraotrs';
import { GoogleLoginDto } from './dto/google-login.dto';
import { RefreshTokenDto } from './dto/refresh.dto';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from './decorator/roles.decorator';

@ApiTags('Auth')
@Public()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('register')
  @ApiOperation({ summary: 'Register user and send OTP' })
  @ApiResponse({ status: HttpStatus.CREATED })
  async register(@Body() body: RegisterDto) {
    return this.authService.register(body);
  }

  @Post('login')
  @ApiOperation({ summary: 'Login user' })
  async login(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  @Post('force-login')
  @ApiOperation({ summary: 'Force login user (clears previous sessions)' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Force login successful' })
  @ApiResponse({ status: HttpStatus.UNAUTHORIZED, description: 'Invalid credentials' })
  async forceLogin(@Body() body: ForceLoginDto) {
    return this.authService.forceLogin(body);
  }

  @ApiBearerAuth('jwt')
  @Post('logout')
  @ApiOperation({ summary: 'Logout user (invalidate session)' })
  logout(@Req() req: Request) {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    return this.authService.logout(token);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify OTP and activate account' })
  async verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto);
  }

  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiBody({ type: RefreshTokenDto })
  async refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refreshToken(dto.refreshToken);
  }

  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resend OTP' })
  async resendOtp(@Body() dto: ResendOtpDto) {
    return this.authService.resendOtp(dto.email);
  }

  @Post('google-login')
  @Public()
  @ApiOperation({ summary: 'Login with Google (Firebase)' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Google login successful' })
  @HttpCode(HttpStatus.OK)
  async googleLogin(@Body('idToken') idToken: string) {
    return this.authService.googleLogin(idToken);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('user', 'admin')
  @Get('profile')
  getProfile() {
    return 'Accessible by user and admin';
}

}
