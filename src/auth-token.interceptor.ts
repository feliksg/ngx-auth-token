import { Inject, Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { AuthTokenService } from './auth-token.service';

@Injectable()
export class AuthTokenInterceptor implements HttpInterceptor {
  constructor(public authTokenService: AuthTokenService ) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    this.authTokenService.setCurrentAuthHeaders();

    const authHeaders = this.authTokenService.currentAuthHeaders;
    authHeaders.keys().forEach((key) => req.headers.append(key, authHeaders.get(key)));

    const authReq = req.clone({ headers: req.headers });

    return next.handle(authReq);
  }
}
