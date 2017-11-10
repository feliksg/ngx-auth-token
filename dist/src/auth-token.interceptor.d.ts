import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { AuthTokenService } from './auth-token.service';
export declare class AuthTokenInterceptor implements HttpInterceptor {
    authTokenService: AuthTokenService;
    constructor(authTokenService: AuthTokenService);
    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>>;
}
