import { IsString, IsBoolean, IsOptional, IsUrl, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class IdentityProviderConfigDto {
  @ApiProperty({ type: String, format: 'uuid' })
  @IsUUID()
  id: string;

  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty({ example: 'https://accounts.google.com' })
  @IsUrl()
  issuer_uri: string;
  
  @ApiProperty({ example: 'https://accounts.google.com/.well-known/openid-configuration' })
  @IsUrl()
  well_known_uri: string;

  @ApiProperty()
  @IsString()
  client_id: string;

  @ApiProperty()
  @IsString()
  client_secret_name: string;

  @ApiProperty({ example: 'openid email profile' })
  @IsString()
  scopes: string;

  @ApiProperty()
  @IsBoolean()
  is_active: boolean;

  @ApiProperty()
  @IsBoolean()
  supports_refresh_token: boolean;
  
  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;
}

export class IdentityProviderConfigCreateDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty({ example: 'https://accounts.google.com' })
  @IsUrl()
  issuer_uri: string;
  
  @ApiProperty({ example: 'https://accounts.google.com/.well-known/openid-configuration' })
  @IsUrl()
  well_known_uri: string;

  @ApiProperty()
  @IsString()
  client_id: string;

  @ApiProperty()
  @IsString()
  client_secret_name: string;

  @ApiProperty({ example: 'openid email profile' })
  @IsString()
  scopes: string;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  is_active?: boolean = true;

  @ApiProperty()
  @IsBoolean()
  supports_refresh_token: boolean;
}

export class IdentityProviderConfigUpdateDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'https://accounts.google.com' })
  @IsOptional()
  @IsUrl()
  issuer_uri?: string;
  
  @ApiPropertyOptional({ example: 'https://accounts.google.com/.well-known/openid-configuration' })
  @IsOptional()
  @IsUrl()
  well_known_uri?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  client_id?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  client_secret_name?: string;

  @ApiPropertyOptional({ example: 'openid email profile' })
  @IsOptional()
  @IsString()
  scopes?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  is_active?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  supports_refresh_token?: boolean;
}
