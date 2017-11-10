import { NgModule, ModuleWithProviders, Optional, SkipSelf, Provider, InjectionToken } from '@angular/core';
import { AuthTokenInterceptor } from './auth-token.interceptor';
import { AuthTokenService } from './auth-token.service';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthTokenOptions } from './auth-token.model';
import { AUTH_TOKEN_OPTIONS } from './auth-token.options';

export * from './auth-token.interceptor';
export * from './auth-token.service';
export * from './auth-token.model';
export * from './auth-token.options';


export interface TokenAuthModuleOptions {
  authTokenOptionsProvider?: Provider;
  config?: AuthTokenOptions;
}

@NgModule()
export class AuthTokenModule {

  constructor(@Optional() @SkipSelf() parentModule: AuthTokenModule) {
    if (parentModule) {
      throw new Error('AuthTokenModule is already loaded. It should only be imported in your application\'s main module.');
    }
  }

  static forRoot(options: TokenAuthModuleOptions): ModuleWithProviders {
    return {
      ngModule: AuthTokenModule,
      providers: [
        {
          provide: HTTP_INTERCEPTORS,
          useClass: AuthTokenInterceptor,
          multi: true
        },
        options.authTokenOptionsProvider ||
        {
          provide: AUTH_TOKEN_OPTIONS,
          useValue: options.config
        },
        AuthTokenService
      ]
    };
  }
}
