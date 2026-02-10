import { Body, Controller, HttpStatus, Post } from '@nestjs/common';
import { MailService } from '../mail/mail.service';
import { ContactUsDto } from './dto/contact-us.dto';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Public } from '../common/decorators/public.decoraotrs';

@ApiTags('Contact Us')
@Controller('contact-us')
export class ContactController {
  constructor(private readonly mailService: MailService) { }

  @Post()
  @Public()
  @ApiOperation({ summary: 'Submit Contact Us form' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Message sent successfully',
  })
  async contactUs(@Body() dto: ContactUsDto) {
    await this.mailService.sendContactUsEmail(dto);
    return {
      data: {
        status: true,
        message: 'Your message has been sent successfully',
      },
    };
  }
}
