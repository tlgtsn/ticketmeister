import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    // Generate the password hash
    const hash = await argon.hash(dto.password);

    try {
      // Save the new user in the database
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      // If the email is already in use, throw an error
      if (error.code === 'P2002') {
        throw new ForbiddenException(
          'Credentials taken',
        );
      }

      // Otherwise, throw the original error
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // Find the user by email
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    // if user does not exist, throw an error
    if (!user)
      throw new ForbiddenException(
        'Credentials are incorrect',
      );

    // Compare the password hash with the password
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );
    // if the password is incorrect, throw an error
    if (!pwMatches)
      throw new ForbiddenException(
        'Credentials are incorrect',
      );

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.sign(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return { access_token: token };
  }
}
