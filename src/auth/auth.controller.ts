// src/auth/auth.controller.ts
import { 
  Controller, 
  Post, 
  Body, 
  Get, 
  Param, 
  UseGuards, 
  Req, 
  BadRequestException,
  Logger 
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";
import { InitQrDto } from "./dto/init-qr.dto";
import { JwtAuthGuard } from "./jwt-auth.guard";
import { WalletConnectService } from "src/wallet/wallet.service";

// Define the type for the approval result
interface ApprovalResult {
  topic: string;
  accessToken: string;
  user: {
    id: string;
    walletAddress: string;
    fullName: string;
    role: string;
  };
}

@Controller("auth")
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private auth: AuthService,
    private walletConnectService: WalletConnectService
  ) {}

  @Post("register")
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Post("login")
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
  }

  /**
   * INIT QR SESSION (unchanged)
   * Returns:
   *  - sessionId
   *  - challenge
   *  - base64 payload
   */
  @Post("qr/init")
  initQr(@Body() dto: InitQrDto) {
    return this.auth.initQrSession(dto);
  }

  /**
   * NEW:
   * Complete WalletConnect login flow in ONE CALL.
   * 1. Client calls /auth/qr/init
   * 2. Then calls /auth/qr/pair-and-wait with that sessionId
   * 3. This call waits for wallet approval → returns accessToken + user
   */
  // @Post("qr/pair-and-wait")
  // async pairQrAndWait(@Body() body: { sessionId: string; timeoutMs?: number }) {
  //   const { sessionId, timeoutMs = 120000 } = body;

  //   try {
  //     const { uri, approvalPromise } = await this.walletConnectService.pairAndApproveQr(sessionId, timeoutMs);

  //     // Wait for approval with timeout
  //     const result = await Promise.race([
  //       approvalPromise as Promise<ApprovalResult>,
  //       new Promise<never>((_, reject) => 
  //         setTimeout(() => reject(new Error('Operation timed out')), timeoutMs)
  //       )
  //     ]);

  //     return {
  //       wcUri: uri,
  //       approved: true,
  //       topic: result.topic,
  //       accessToken: result.accessToken,
  //       user: {
  //         id: result.user.id,
  //         walletAddress: result.user.walletAddress,
  //         fullName: result.user.fullName,
  //         role: result.user.role,
  //       },
  //     };
  //   } catch (error: any) {
  //     this.logger.error('QR pair and wait failed', error);
  //     throw new BadRequestException(error.message);
  //   }
  // }

  @Post("qr/pair-and-wait")
async pairQrAndWait(@Body() body: { sessionId: string; timeoutMs?: number }) {
  const { sessionId, timeoutMs = 120000 } = body;

  try {
    const { uri, approvalPromise } = await this.walletConnectService.pairAndApproveQr(sessionId, timeoutMs);

    // Return the URI immediately for QR scanning
    // The client can poll /auth/qr/status/:id for approval status
    return {
      wcUri: uri,
      message: "Scan this QR code with your wallet to login",
      sessionId: sessionId,
      statusCheckUrl: `/auth/qr/status/${sessionId}`
    };

    // If you want to wait for approval in this call, uncomment below:
    /*
    const result = await approvalPromise;
    return {
      wcUri: uri,
      approved: true,
      topic: result.topic,
      accessToken: result.accessToken,
      user: result.user,
    };
    */
  } catch (error: any) {
    this.logger.error('QR pair and wait failed', error);
    throw new BadRequestException(error.message);
  }
}

  /**
   * CHECK QR STATUS (unchanged)
   * Frontend can poll if not using pair-and-wait.
   */
  @Get("qr/status/:id")
  checkQr(@Param("id") id: string) {
    return this.auth.checkQrStatus(id);
  }

  /**
   * GET PROFILE (unchanged)
   */
  @UseGuards(JwtAuthGuard)
  @Get("profile")
  getProfile(@Req() req) {
    return this.auth.getUserProfile(req.user.userId);
  }
}