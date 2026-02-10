import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from 'src/auth/schema/user.schema';
import { UpdateRoleDto } from './dto/update-role.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<UserDocument>,
  ) {}

  async getAllUsers(page = 1, limit = 10, search?: string) {
    const skip = (page - 1) * limit;

    const filter: any = {
      role: { $ne: 'admin' }, // 👈 hide admin users
    };

    // 🔍 SEARCH by name or email
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }

    const [users, total] = await Promise.all([
      this.userModel
        .find(filter)
        .select('name email isVerified status createdAt updatedAt')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .lean(),

      // ⚠️ total must respect the SAME filter
      this.userModel.countDocuments(filter),
    ]);

    return {
      data: {
        status: true,
        users,
        total,
        page,
        limit,
      },
    };
  }

  async updateUserRole(dto: UpdateRoleDto, adminEmail: string) {
    const { email, role } = dto;
    if (email === adminEmail) {
      throw new BadRequestException('You cannot change your own role');
    }

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.role === role) {
      throw new BadRequestException(`User already has role ${role}`);
    }

    user.role = role;
    await user.save();

    return {
      data: {
        status: true,
        message: 'User role updated successfully',
        email: user.email,
        role: user.role,
      },
    };
  }
}
