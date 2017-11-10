import { ModuleWithProviders, Provider } from '@angular/core';
import { AuthTokenOptions } from './auth-token.model';
export * from './auth-token.interceptor';
export * from './auth-token.service';
export * from './auth-token.model';
export * from './auth-token.options';
export interface TokenAuthModuleOptions {
    authTokenOptionsProvider?: Provider;
    config?: AuthTokenOptions;
}
export declare class AuthTokenModule {
    constructor(parentModule: AuthTokenModule);
    static forRoot(options: TokenAuthModuleOptions): ModuleWithProviders;
}
