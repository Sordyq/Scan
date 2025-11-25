// src/auth/dto/init-qr.dto.ts
import { IsEnum, IsOptional } from 'class-validator';

export class InitQrDto {
  @IsOptional()
  @IsEnum(['ISSUER', 'VERIFIER'])
  role?: 'ISSUER' | 'VERIFIER';
}