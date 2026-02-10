import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { OTP, OTPDocument } from './schemas/otp.schema';
import { MailService } from '../mail/mail.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';

@Injectable()
export class OtpService {
  constructor(
    @InjectModel(OTP.name) private otpModel: Model<OTPDocument>,
    private mailService: MailService,
  ) {}

  async generateAndSendOtp(email: string) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await this.otpModel.findOneAndUpdate(
      { email },
      { otp, expiresAt },
      { upsert: true, new: true },
    );

    await this.mailService.sendOtpEmail(email, otp);

    return {
      message: 'OTP sent successfully',
      otp,
    };
  }

  async verifyOtp(data: VerifyOtpDto) {
    const otpRecord = await this.otpModel.findOne({
      email: data.email,
      otp: data.otp,
    });

    if (!otpRecord) {
      return { success: false, message: 'Invalid OTP' };
    }

    if (otpRecord.expiresAt < new Date()) {
      return { success: false, message: 'OTP expired' };
    }

    await this.otpModel.deleteOne({ email: data.email });
    return { success: true, message: 'OTP verified' };
  }
}
