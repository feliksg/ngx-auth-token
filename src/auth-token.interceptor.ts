import { Injector, Injectable } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpHeaders, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { AuthTokenService } from './auth-token.service';
import 'rxjs/add/operator/do';

@Injectable()
export class AuthTokenInterceptor implements HttpInterceptor {
  authTokenService: AuthTokenService;

  constructor(private inj: Injector) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    this.authTokenService = this.inj.get(AuthTokenService);

    const headers: any = {};

    if (req.headers && req.headers.keys().length) {
      req.headers.keys().forEach(key => { headers[key] = req.headers.get(key); });
    }

    const authHeaders = this.authTokenService.getCurrentAuthHeaders();
    if (authHeaders && authHeaders.keys().length) {
      authHeaders.keys().forEach(key => { headers[key] = authHeaders.get(key); });
    }

    const httpHeaders: HttpHeaders = new HttpHeaders(headers);
    const authReq = req.clone({ headers: httpHeaders });

    return next.handle(authReq).do((event: HttpEvent<any>) => {
      if (event instanceof HttpResponse) {
        this.authTokenService.getAuthHeadersFromResponse(event.headers);
      }
    });
  }
}
