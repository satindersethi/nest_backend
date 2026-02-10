import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;
export type UserRole = 'user' | 'admin';

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop()
  password: string;

  @Prop()
  name: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({
    type: String,
    enum: ['active', 'deactive'] as const,
    default: 'deactive',
  })
  status: 'active' | 'deactive';

  @Prop({ default: 0 })
  failedLoginAttempts: number;

  @Prop({ default: null })
  lastFailedLoginAt: Date;

  @Prop({ default: false })
  isLocked: boolean;

  @Prop()
  googleUid?: string;

  @Prop({ default: 'user' })
  provider?: 'user' | 'google';

  @Prop({
    type: String,
    enum: ['user', 'admin'] as const,
    default: 'user',
  })
  role: UserRole;
}

export const UserSchema = SchemaFactory.createForClass(User);
