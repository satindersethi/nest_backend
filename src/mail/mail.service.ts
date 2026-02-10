import { Injectable } from '@nestjs/common';
import { createTransport, Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: Transporter;

  constructor() {
    this.transporter = createTransport({
      host: process.env.SMTP_HOST ?? '',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: String(process.env.SMTP_USER),
        pass: String(process.env.SMTP_PASS),
      },
    });
  }

  async sendOtpEmail(email: string, otp: string): Promise<void> {
    const html = this.getOtpHtml(otp);

    await this.transporter.sendMail({
      from: `"Test App" <${String(process.env.SMTP_USER)}>`,
      to: email,
      subject: 'Your OTP Code',
      html,
    });
  }

  async sendContactUsEmail(data: {
    name: string;
    email: string;
    contactNumber: string;
    message: string;
  }): Promise<void> {
    const html = `
  <div style="background:#f5f7fb;padding:30px 0;font-family:Arial,Helvetica,sans-serif;">
    <div style="
      max-width:600px;
      margin:auto;
      background:#ffffff;
      border-radius:10px;
      overflow:hidden;
      box-shadow:0 4px 12px rgba(0,0,0,0.08);
    ">
      
      <!-- Header -->
      <div style="
        background:linear-gradient(135deg,#4f46e5,#6366f1);
        padding:20px 30px;
        color:#ffffff;
      ">
        <h2 style="margin:0;font-size:22px;">📩 New Contact Us Message</h2>
        <p style="margin:5px 0 0;font-size:14px;opacity:0.9;">
          A user has submitted a contact request
        </p>
      </div>

      <!-- Body -->
      <div style="padding:30px;color:#333333;">
        
        <table style="width:100%;border-collapse:collapse;">
          <tr>
            <td style="padding:8px 0;font-weight:bold;width:150px;">Name</td>
            <td style="padding:8px 0;">${data.name}</td>
          </tr>
          <tr>
            <td style="padding:8px 0;font-weight:bold;">Email</td>
            <td style="padding:8px 0;">
              <a href="mailto:${data.email}" style="color:#4f46e5;text-decoration:none;">
                ${data.email}
              </a>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 0;font-weight:bold;">Contact Number</td>
            <td style="padding:8px 0;">${data.contactNumber}</td>
          </tr>
        </table>

        <hr style="margin:24px 0;border:none;border-top:1px solid #e5e7eb;" />

        <p style="font-weight:bold;margin-bottom:8px;">Message</p>
        <div style="
          background:#f9fafb;
          padding:16px;
          border-radius:8px;
          border-left:4px solid #4f46e5;
          line-height:1.6;
        ">
          ${data.message}
        </div>

      </div>

      <!-- Footer -->
      <div style="
        background:#f3f4f6;
        padding:16px 30px;
        font-size:12px;
        color:#6b7280;
        text-align:center;
      ">
        You can reply directly to this email to respond to the user.
      </div>
    </div>
  </div>
  `;

    await this.transporter.sendMail({
      from: `"Website Contact" <${process.env.SMTP_USER}>`,
      to: process.env.SMTP_USER,
      replyTo: data.email,
      subject: 'New Contact Us Submission',
      html,
    });
  }

  private getOtpHtml(otp: string): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2 style="color: #333;">Verify Your Email</h2>
        <p>Your One-Time Password (OTP) is:</p>

        <div style="
          font-size: 28px;
          font-weight: bold;
          letter-spacing: 6px;
          background: #f4f4f4;
          padding: 16px;
          text-align: center;
          border-radius: 8px;
          margin: 24px 0;
        ">
          ${otp}
        </div>

        <p>This OTP is valid for <b>5 minutes</b>.</p>
        <p style="color: #777; font-size: 12px;">
          If you didn’t request this, you can safely ignore this email.
        </p>
      </div>
    `;
  }
}
