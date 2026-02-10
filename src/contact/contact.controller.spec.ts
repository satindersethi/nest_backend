import { Body, Controller, HttpStatus, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { MailService } from '../mail/mail.service';
import { ContactUsDto } from './dto/contact-us.dto';
import { Public } from '../common/decorators/public.decoraotrs';

@ApiTags('Contact')
@Controller('contact')
export class ContactController {
  constructor(private readonly mailService: MailService) { }

  @Post('us')
  @Public()
  @ApiOperation({ summary: 'Submit Contact Us form' })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Contact message sent successfully',
  })
  async contactUs(@Body() body: ContactUsDto) {
    await this.mailService.sendContactUsEmail(body);

    return {
      data: {
        status: true,
        message: 'Your message has been sent successfully',
      },
    };
  }
}
