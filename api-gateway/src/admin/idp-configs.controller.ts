import {
  Controller, Get, Post, Put, Delete, Param, Body, Query,
  UseGuards, ParseUUIDPipe, HttpStatus, HttpCode, UsePipes
} from '@nestjs/common';
import { AuthRelayService } from '../auth/auth-relay.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import {
  IdentityProviderConfigDto,
  IdentityProviderConfigCreateDto,
  IdentityProviderConfigUpdateDto,
  IdentityProviderConfigCreateSchema,
  IdentityProviderConfigUpdateSchema
} from '@teamvitality/shared-dtos';
import { ZodValidationPipe } from 'nestjs-zod';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiParam, ApiQuery } from '@nestjs/swagger';

@ApiTags('Admin - Identity Provider Configurations')
@ApiBearerAuth()
@Controller('admin/idp-configs')
@UseGuards(JwtAuthGuard, RolesGuard)
export class IdpConfigsController {
  constructor(private readonly authRelayService: AuthRelayService) {}

  @Post()
  @Roles('Admin')
  @UsePipes(new ZodValidationPipe(IdentityProviderConfigCreateSchema))
  @ApiOperation({ summary: 'Create a new IdP configuration' })
  async create(
    @Body() createDto: IdentityProviderConfigCreateDto,
  ): Promise<IdentityProviderConfigDto> {
    return this.authRelayService.createIdpConfig(createDto);
  }

  @Get()
  @Roles('Admin')
  @ApiOperation({ summary: 'List all IdP configurations' })
  @ApiQuery({ name: 'skip', required: false, type: Number, description: 'Number of records to skip for pagination' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Maximum number of records to return' })
  async findAll(
     @Query('skip') skip?: number, 
     @Query('limit') limit?: number
  ): Promise<IdentityProviderConfigDto[]> {
    return this.authRelayService.listIdpConfigs(skip, limit);
  }

  @Get(':providerId')
  @Roles('Admin')
  @ApiOperation({ summary: 'Get an IdP configuration by ID' })
  @ApiParam({ name: 'providerId', type: String, format: 'uuid', description: 'IdP Configuration ID' })
  async findOne(
    @Param('providerId', ParseUUIDPipe) providerId: string,
  ): Promise<IdentityProviderConfigDto> {
    return this.authRelayService.getIdpConfig(providerId);
  }

  @Put(':providerId')
  @Roles('Admin')
  @UsePipes(new ZodValidationPipe(IdentityProviderConfigUpdateSchema))
  @ApiOperation({ summary: 'Update an IdP configuration by ID' })
  @ApiParam({ name: 'providerId', type: String, format: 'uuid', description: 'IdP Configuration ID' })
  async update(
    @Param('providerId', ParseUUIDPipe) providerId: string,
    @Body() updateDto: IdentityProviderConfigUpdateDto,
  ): Promise<IdentityProviderConfigDto> {
    return this.authRelayService.updateIdpConfig(providerId, updateDto);
  }

  @Delete(':providerId')
  @Roles('Admin')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete an IdP configuration by ID' })
  @ApiParam({ name: 'providerId', type: String, format: 'uuid', description: 'IdP Configuration ID' })
  async remove(@Param('providerId', ParseUUIDPipe) providerId: string): Promise<void> {
    await this.authRelayService.deleteIdpConfig(providerId);
  }
}
