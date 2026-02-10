import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { OtpService } from './otp.service';
import { OTP, OTPSchema } from './schemas/otp.schema';
import { User, UserSchema } from '../auth/schema/user.schema';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: OTP.name, schema: OTPSchema },
      { name: User.name, schema: UserSchema },
    ]),
    MailModule,
  ],
  providers: [OtpService],
  exports: [OtpService],
})
export class OtpModule {}
