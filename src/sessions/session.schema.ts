import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type SessionDocument = Session & Document;

@Schema({ timestamps: true })
export class Session {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  token: string;

    @Prop() 
  refreshToken?: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ type: Date })
  lastUsedAt?: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
