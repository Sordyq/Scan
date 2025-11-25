// src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
  BadRequestException
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from "bcryptjs";
import { JwtService } from "@nestjs/jwt";
import { v4 as uuidv4 } from "uuid";
import * as crypto from "crypto";
import { WalletService } from "./walletService";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private walletService: WalletService
  ) {}

  /**
   * REGISTER USER (unchanged)
   */
  async register(dto) {
    const hash = await bcrypt.hash(dto.password, 10);

    const wallet = this.walletService.generateLightweightWallet();
    const did = this.walletService.generateDID();

    const user = await this.prisma.user.create({
      data: {
        id: uuidv4(),
        email: dto.email,
        password: hash,
        fullName: dto.fullName,
        role: dto.role,
        did: did,
        walletAddress: wallet.address,
        publicKey: wallet.publicKey,
        privateKey: wallet.privateKey,
      },
    });

    return {
      token: this.jwt.sign({
        userId: user.id,
        role: user.role,
        email: user.email,
        did: user.did,
        walletAddress: user.walletAddress,
      }),
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        did: user.did,
        walletAddress: user.walletAddress,
      },
    };
  }

  /**
   * LOGIN USER (unchanged)
   */
  async login(dto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) throw new UnauthorizedException("Invalid email or password");

    const valid = await bcrypt.compare(dto.password, user.password);
    if (!valid) throw new UnauthorizedException("Invalid email or password");

    return {
      token: this.jwt.sign({
        userId: user.id,
        role: user.role,
        email: user.email,
        did: user.did,
        walletAddress: user.walletAddress,
      }),
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        did: user.did,
        walletAddress: user.walletAddress,
        publicKey: user.publicKey,
      },
    };
  }

  /**
   * CREATE QR SESSION (unchanged)
   */
  async initQrSession(dto: { role?: string }) {
    const sessionId = uuidv4();
    const challenge = crypto.randomBytes(32).toString("hex");

    const qr = await this.prisma.qrsession.create({
      data: {
        sessionId,
        challenge,
        // role: dto.role || null,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      },
    });

    const qrPayload = {
      sessionId: qr.sessionId,
      challenge: qr.challenge,
      role: qr.role,
      expiresAt: qr.expiresAt.getTime(),
      type: "wallet_auth",
      message: "Sign this message to authenticate with your wallet",
    };

    const qrPayloadBase64 = Buffer.from(JSON.stringify(qrPayload)).toString("base64");

    return {
      sessionId: qr.sessionId,
      challenge: qr.challenge,
      qrPayload: qrPayloadBase64,
      expiresIn: 300,
    };
  }

  /**
   * THIS WAS USING MANUAL SIGNATURE BEFORE
   * NOW WalletConnect handles signing automatically.
   * This is kept only to support QR polling system.
   */
  async checkQrStatus(sessionId: string) {
    const session = await this.prisma.qrsession.findUnique({
      where: { sessionId },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            fullName: true,
            role: true,
            did: true,
            walletAddress: true,
            publicKey: true,
            createdAt: true,
          },
        },
      },
    });

    if (!session) throw new NotFoundException("Session not found");

    if (session.status === "APPROVED" && session.userId) {
      const userData = session.syncData ? JSON.parse(session.syncData) : session.user;

      return {
        status: "approved",
        accessToken: this.jwt.sign({
          userId: userData.id,
          role: userData.role,
          email: userData.email,
          did: userData.did,
          walletAddress: userData.walletAddress,
        }),
        user: userData,
      };
    }

    if (session.expiresAt < new Date()) {
      return { status: "expired" };
    }

    return { status: "pending" };
  }

  /**
   * GET USER PROFILE (unchanged)
   */
  async getUserProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        fullName: true,
        role: true,
        did: true,
        walletAddress: true,
        publicKey: true,
        createdAt: true,
      },
    });

    if (!user) throw new NotFoundException("User not found");
    return user;
  }
}
