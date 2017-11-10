import { ActivatedRoute, Router, CanActivate } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/share';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/operator/pluck';
import 'rxjs/add/operator/filter';
import { SignInData, RegisterData, UpdatePasswordData, ResetPasswordData, UserData, AuthData, AuthTokenOptions, RequestOptions } from './auth-token.model';
export declare class AuthTokenService implements CanActivate {
    private http;
    private activatedRoute;
    private router;
    defaultOptions: AuthTokenOptions;
    readonly currentUserType: string;
    readonly currentUserData: UserData;
    readonly currentAuthData: AuthData;
    readonly currentAuthHeaders: HttpHeaders;
    private atOptions;
    private atCurrentUserType;
    private atCurrentAuthData;
    private atCurrentUserData;
    constructor(http: HttpClient, config: AuthTokenOptions, activatedRoute: ActivatedRoute, router: Router);
    userSignedIn(): boolean;
    canActivate(): boolean;
    init(options?: AuthTokenOptions): void;
    /**
     *
     * Actions
     *
     */
    registerAccount(registerData: RegisterData): Observable<Response>;
    deleteAccount(): Observable<Response>;
    signIn(signInData: SignInData): Observable<Response>;
    signInOAuth(oAuthType: string): Observable<any>;
    processOAuthCallback(): void;
    signOut(): Observable<Response>;
    validateToken(): Observable<Response>;
    updatePassword(updatePasswordData: UpdatePasswordData): Observable<Response>;
    resetPassword(resetPasswordData: ResetPasswordData): Observable<Response>;
    /**
     *
     * HTTP Wrappers
     *
     */
    get(url: string, options?: RequestOptions): Observable<any>;
    post(url: string, body: any, options?: RequestOptions): Observable<any>;
    put(url: string, body: any, options?: RequestOptions): Observable<any>;
    delete(url: string, options?: RequestOptions): Observable<any>;
    patch(url: string, body: any, options?: RequestOptions): Observable<any>;
    head(url: string, options?: RequestOptions): Observable<any>;
    options(url: string, options?: RequestOptions): Observable<any>;
    setCurrentAuthHeaders(): HttpHeaders;
    private handleResponse(request);
    /**
     *
     * Get Auth Data
     *
     */
    private tryLoadAuthData();
    private getAuthHeadersFromResponse(data);
    private getAuthDataFromPostMessage(data);
    private getAuthDataFromStorage();
    private getAuthDataFromParams();
    /**
     *
     * Set Auth Data
     *
     */
    private setAuthData(authData);
    /**
     *
     * Validate Auth Data
     *
     */
    private checkAuthData(authData);
    /**
     *
     * Construct Paths / Urls
     *
     */
    private getUserPath();
    private getApiPath();
    private getOAuthPath(oAuthType);
    private getOAuthUrl(oAuthPath, callbackUrl, windowType);
    /**
     *
     * OAuth
     *
     */
    private requestCredentialsViaPostMessage(authWindow);
    private oAuthWindowResponseFilter(data);
    /**
     *
     * Utilities
     *
     */
    private getUserTypeByName(name);
}
