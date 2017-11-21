import { NgModule, ModuleWithProviders, Optional, SkipSelf } from '@angular/core';

import { AuthTokenInterceptor } from './auth-token.interceptor';
import { AuthTokenService } from './auth-token.service';
import { HTTP_INTERCEPTORS } from '@angular/common/http';

@NgModule()
export class AuthTokenModule {

  constructor(@Optional() @SkipSelf() parentModule: AuthTokenModule) {
    if (parentModule) {
      throw new Error('AuthTokenModule is already loaded. It should only be imported in your application\'s main module.');
    }
  }

  static forRoot(): ModuleWithProviders {
    return {
      ngModule: AuthTokenModule,
      providers: [
        { provide: HTTP_INTERCEPTORS, useClass: AuthTokenInterceptor, multi: true },
        AuthTokenService
      ]
    };
  }
}
