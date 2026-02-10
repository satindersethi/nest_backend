import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { User, UserDocument } from './schema/user.schema';
import { OtpService } from '../otp/otp.service';
import { VerifyOtpDto } from '../otp/dto/verify-otp.dto';
import { ForceLoginDto, LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { Session, SessionDocument } from '../sessions/session.schema';
import admin from '../firebase/firebase-admin';
import { DecodedIdToken } from 'firebase-admin/auth';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<UserDocument>,

    @InjectModel(Session.name)
    private readonly sessionModel: Model<SessionDocument>,
    private readonly otpService: OtpService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) { }

  private async generateTokensAndCreateSession(
    user: UserDocument,
    session?: SessionDocument,
  ) {
    const payload = {
      sub: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const access_token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRES'),
    });
    const refresh_token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRES'),
    });

    const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);

    if (session) {
      session.token = hashedRefreshToken;
      await session.save();
    } else {
      await this.sessionModel.create({
        userId: user._id,
        token: hashedRefreshToken,
        isActive: true,
      });
    }
    return {
      access_token,
      refresh_token,
    };
  }

  // ---------------- REGISTER ----------------
  async register(body: RegisterDto) {
    const { email, password, name } = body;
    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.userModel.create({
      email,
      password: hashedPassword,
      name,
      isVerified: false,
      status: 'deactive',
    });
    await this.otpService.generateAndSendOtp(email);
    return {
      data: {
        status: true,
        message: 'OTP sent successfully',
        email: user.email,
        role: user.role,
      },
    };
  }

  // ---------------- LOGIN ----------------
  async login(data: LoginDto) {
    const MAX_ATTEMPTS = 3;
    const LOCK_TIME = 2 * 60 * 1000;
    const user = await this.userModel.findOne({ email: data.email });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.status) {
      throw new UnauthorizedException(
        'User is now deactivated, please contact admin',
      );
    }

    if (user.isLocked) {
      if (user.lastFailedLoginAt) {
        const now = new Date();
        const diff = now.getTime() - new Date(user.lastFailedLoginAt).getTime();
        if (diff > LOCK_TIME) {
          user.isLocked = false;
          user.failedLoginAttempts = 0;
          user.lastFailedLoginAt = null;
          await user.save();
        } else {
          throw new BadRequestException(
            'Login attempt reached.Retry after 2 minutes',
          );
        }
      } else {
        throw new BadRequestException(
          'Login attempt reached.Retry after 2 minutes',
        );
      }
    }

    const isMatch = await bcrypt.compare(data.password, user.password);
    if (!isMatch) {
      user.failedLoginAttempts += 1;
      user.lastFailedLoginAt = new Date();
      if (user.failedLoginAttempts >= MAX_ATTEMPTS) {
        user.isLocked = true;
      }

      await user.save();
      throw new BadRequestException('Invalid credentials');
    }

    user.failedLoginAttempts = 0;
    user.lastFailedLoginAt = null;
    await user.save();

    if (!user.isVerified) {
      return {
        data: {
          status: false,
          message: 'Account not verified',
          code: 'NOT_VERIFIED',
        },
      };
    }

    const activeSessions = await this.sessionModel
      .find({ userId: user._id, isActive: true })
      .sort({ createdAt: 1 });

    if (activeSessions.length >= 3) {
      return {
        data: {
          status: false,
          message: 'Maximum limit reached',
          code: 'LIMIT_EXCEED',
          email: user.email,
        },
      };
    }
    const { access_token, refresh_token } =
      await this.generateTokensAndCreateSession(user);

    return {
      data: {
        status: true,
        message: 'Login successful',
        access_token,
        role: user.role,
        refresh_token,
      },
    };
  }

  // ----------------------Force login---------------------
  async forceLogin(body: ForceLoginDto) {
    const user = await this.userModel.findOne({
      email: body.email.toLocaleLowerCase(),
    });
    await this.sessionModel.deleteMany({ userId: user._id, isActive: true });
    const { access_token, refresh_token } =
      await this.generateTokensAndCreateSession(user);
    return {
      data: {
        status: true,
        message: 'Login successful - all devices logged out',
        access_token,
        role: user.role,
        refresh_token,
      },
    };
  }

  // -------------------- VERIFY OTP --------------------
  async verifyOtp(dto: VerifyOtpDto) {
    const { email } = dto;
    const result = await this.otpService.verifyOtp(dto);
    if (!result.success) {
      throw new UnauthorizedException(result.message);
    }
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    user.isVerified = true;
    user.status = 'active';

    await user.save();

    const { access_token, refresh_token } =
      await this.generateTokensAndCreateSession(user);

    return {
      data: {
        status: true,
        message: 'OTP verified successfully',
        access_token,
        role: user.role,
        refresh_token,
      },
    };
  }

  // ---------------- RESEND OTP ----------------
  async resendOtp(email: string) {
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new BadRequestException('No account found with this email');
    }

    if (user.isVerified) {
      throw new BadRequestException('Account is already verified');
    }

    await this.otpService.generateAndSendOtp(email);

    return {
      data: {
        status: true,
        message: 'New OTP sent successfully',
      },
    };
  }

  //----------------------firebase------------------------------

  async googleLogin(idToken: string) {
    let decodedToken: DecodedIdToken;

    try {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } catch {
      throw new UnauthorizedException('Invalid Google token');
    }

    const { email, name, email_verified, uid } = decodedToken;

    if (!email) {
      throw new BadRequestException('Google account has no email');
    }
    let user = await this.userModel.findOne({ email });
    if (!user) {
      user = await this.userModel.create({
        email,
        name,
        isVerified: email_verified,
        status: 'active',
        provider: 'google',
        googleUid: uid,
      });
    }

    if (user.status !== 'active') {
      throw new UnauthorizedException(
        'User is deactivated, please contact admin',
      );
    }

    if (user.provider !== 'google') {
      throw new BadRequestException(
        'This email is registered using email & password login',
      );
    }

    const activeSessions = await this.sessionModel
      .find({ userId: user._id, isActive: true })
      .sort({ createdAt: 1 });

    if (activeSessions.length >= 3) {
      return {
        data: {
          status: false,
          message: 'Maximum limit reached',
          code: 'LIMIT_EXCEED',
          email: user.email,
        },
      };
    }

    const { access_token, refresh_token } =
      await this.generateTokensAndCreateSession(user);
    return {
      data: {
        status: true,
        message: 'Google login successful',
        access_token,
        refresh_token,
        role: user.role,
      },
    };
  }

  async logout(accessToken: string) {
    if (!accessToken) {
      throw new UnauthorizedException('Token missing');
    }

    const sessions = await this.sessionModel.find({ isActive: true });

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(accessToken, session.token);
      if (isMatch) {
        await this.sessionModel.deleteOne({ _id: session._id });
        return {
          data: {
            status: true,
            message: 'Logged out successfully',
          },
        };
      }
    }

    throw new UnauthorizedException('Invalid session');
  }

  // -----------Refersh token ---------------------------

  async refreshToken(refreshToken: string) {
    let payload: any;

    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid token');
    }

    const sessions = await this.sessionModel.find({
      userId: new Types.ObjectId(payload.sub),
      isActive: true,
    });

    let matchedSession: SessionDocument | null = null;

    for (const session of sessions) {
      const isMatch = await bcrypt.compare(refreshToken, session.token);
      if (isMatch) {
        matchedSession = session;
        break;
      }
    }

    if (!matchedSession) {
      throw new UnauthorizedException('Session expired');
    }

    const user = await this.userModel.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const { access_token, refresh_token } =
      await this.generateTokensAndCreateSession(user, matchedSession);

    return {
      data: {
        status: true,
        access_token,
        refresh_token,
      },
    };
  }
}
